#include "queryBadMalloc.hpp"
#include <json/json.h>
#include <regex>
#include <vector>

#include "llvm_headers.hpp"

using namespace clang;
using namespace clang::ast_matchers;

std::vector<CheckResult> mallocResults;

extern std::string function_name;

bool isMalloc(const CallExpr *call) {
  static const std::regex malloc_regex(".*malloc.*");
  if (const FunctionDecl *callee = call->getDirectCallee()) {
    std::string name = callee->getNameAsString();
    if (regex_match(name, malloc_regex)) {
      return true;
    }
  }
  return false;
}

/// Class to handle matches for bad reference expressions
class BadRefExprCallback : public MatchFinder::MatchCallback {
public:
  int count = 0;

  void run(const MatchFinder::MatchResult &Result) override {
    count += 1;
    if (const IfStmt *ifStmt = Result.Nodes.getNodeAs<IfStmt>("if")) {
      std::string varName;
      if (auto var = Result.Nodes.getNodeAs<VarDecl>("var"))
        varName = var->getName();
      else {
        if (auto var = Result.Nodes.getNodeAs<MemberExpr>("var")) {
          varName = var->getMemberNameInfo().getAsString();
        }
      }
    }
  }
};

/// Check if the variable is checked against NULL in any if statement.
/// @returns true if not checked, false if checked.
bool findBadRefExpr(const VarDecl *var, ASTContext &context,
                    const MemberExpr *mem = nullptr) {
  MatchFinder finder;
  BadRefExprCallback callback;

  auto NullMatcher = hasDescendant(integerLiteral(equals(0)));
  auto CMPMatcher = anyOf(hasOperatorName("=="), hasOperatorName("!="));

  if (!mem) {
    finder.addMatcher(
        ifStmt(hasCondition(binaryOperator(
                   CMPMatcher,
                   hasEitherOperand(ignoringParenImpCasts(
                       declRefExpr(to(varDecl(equalsNode(var)).bind("var"))))),
                   hasEitherOperand(NullMatcher))))
            .bind("if"),
        &callback);
    finder.addMatcher(
        ifStmt(hasCondition(unaryOperator(
                   hasOperatorName("!"),
                   hasUnaryOperand(ignoringParenImpCasts(
                       declRefExpr(to(varDecl(equalsNode(var)).bind("var")))))

                       )))
            .bind("if"),
        &callback);
  } else {
    DeclRefExpr *base;
    if (auto cast = dyn_cast<ImplicitCastExpr>(mem->getBase())) {
      base = dyn_cast<DeclRefExpr>(cast->getSubExpr());
    } else {
      base = dyn_cast<DeclRefExpr>(mem->getBase());
    }
    if (!base) {
      return false;
    }
    VarDecl *baseVar = dyn_cast<VarDecl>(base->getDecl());

    auto BaseMatcher =
        ignoringParenImpCasts(declRefExpr(to(varDecl(equalsNode(baseVar)))));
    auto MemberMatcher =
        memberExpr(hasDeclaration(fieldDecl(equalsNode(mem->getMemberDecl()))),
                   hasObjectExpression(BaseMatcher));
    finder.addMatcher(ifStmt(hasCondition(binaryOperator(
                                 CMPMatcher,
                                 hasEitherOperand(ignoringParenImpCasts(
                                     MemberMatcher.bind("var"))),
                                 hasEitherOperand(NullMatcher))))
                          .bind("if"),
                      &callback);
    finder.addMatcher(
        ifStmt(hasCondition(unaryOperator(hasOperatorName("!"),
                                          hasUnaryOperand(ignoringParenImpCasts(
                                              MemberMatcher.bind("var"))))))
            .bind("if"),
        &callback);
  }

  finder.matchAST(context);
  if (callback.count == 0) {
    return true;
  }
  return false;
}

void emitBadMallocDiag(const Stmt *call, ASTContext &context) {
  auto loc = call->getBeginLoc();
  auto filename = context.getSourceManager().getFilename(loc).str();
  if (filename == "") {
    return;
  }
  mallocResults.push_back(CheckResult{
      filename,
      function_name,
      (int)context.getSourceManager().getSpellingLineNumber(loc),
  });
  /*
  unsigned DiagID = context.getDiagnostics().getCustomDiagID(
      DiagnosticsEngine::Warning,
      "malloc call result is not checked against NULL");
  context.getDiagnostics().Report(call->getBeginLoc(), DiagID);
  */
}

/// Look for malloc calls in the statement tree
/// If found, look for parent VarDecl and check if it is checked against NULL
bool queryBadMalloc(const Stmt *s, ASTContext &context) {
  if (!s)
    return false;
  if (const CallExpr *call = dyn_cast<CallExpr>(s)) {
    return isMalloc(call);
  }
  for (auto child : s->children()) {
    bool is_malloc = queryBadMalloc(child, context);
    if (is_malloc) {
      // Look for assigned variable

      std::vector<const DynTypedNode *> queue;
      for (auto parent : context.getParents(*child)) {
        if (parent.get<Stmt>()) {
          queue.push_back(&parent);
        }
      }
      while (queue.size() > 0) {
        auto node = queue.back();
        queue.pop_back();
        if (auto stmt = node->get<VarDecl>()) {
          if (findBadRefExpr(stmt, context)) {
            emitBadMallocDiag(s, context);
          }
          return false;
        }
        if (auto stmt = node->get<BinaryOperator>()) {
          if (stmt->isAssignmentOp()) {
            // LHS of an assignment DeclRefExpr as a reference to
            // variable.
            if (auto lhs = dyn_cast<DeclRefExpr>(stmt->getLHS())) {
              if (auto var = dyn_cast<VarDecl>(lhs->getDecl())) {
                if (findBadRefExpr(var, context)) {
                  emitBadMallocDiag(s, context);
                }
                return false;
              }
            }

            // We also need to handle member expressions,
            // e.g., f->a = malloc(...)
            if (auto lhs = dyn_cast<MemberExpr>(stmt->getLHS())) {
              if (findBadRefExpr(nullptr, context, lhs)) {
                emitBadMallocDiag(s, context);
              }
              return false;
            }
          }
        }
        for (auto parent : context.getParents(*node)) {
          queue.push_back(&parent);
        }
      }
    }
  }
  return false;
}

void badMallocEmitJson(llvm::StringRef filename) {
  auto results = ResultsToJson(mallocResults, "Bad Malloc");
  std::string fname = filename.str() + ".jsonl";
  FILE *f = fopen(fname.c_str(), "a");
  for (const auto &res : results) {
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    std::string output = Json::writeString(builder, res);

    fputs(output.c_str(), f);
    fputs("\n", f);
  }
  fclose(f);
}
