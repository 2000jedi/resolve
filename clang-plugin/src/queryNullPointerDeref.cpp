#include <utility>

#include "llvm_headers.hpp"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchers.h"

using namespace clang;
using namespace clang::ast_matchers;

static std::vector<CheckResult> NPDResults;

class CheckDerefCallback : public MatchFinder::MatchCallback {
public:
  ASTContext &context;
  CheckDerefCallback(ASTContext &ctx) : context(ctx) {}
  void run(const MatchFinder::MatchResult &Result) override {
    SourceLocation loc;
    if (const auto *memberExpr =
            Result.Nodes.getNodeAs<MemberExpr>("memberExpr")) {
      loc = memberExpr->getBeginLoc();
    }

    if (const auto *unaryOp =
            Result.Nodes.getNodeAs<UnaryOperator>("unaryOp")) {
      loc = unaryOp->getBeginLoc();
    }

    auto filename = context.getSourceManager().getFilename(loc).str();
    NPDResults.push_back(CheckResult{
        filename,
        function_name,
        (int)context.getSourceManager().getSpellingLineNumber(loc),
    });
  }
};

/// Class to handle matches for FPE
class NullVarCallback : public MatchFinder::MatchCallback {
public:
  ASTContext &context;
  const IfStmt &if_stmt;
  NullVarCallback(ASTContext &ctx, const IfStmt &if_stmt)
      : context(ctx), if_stmt(if_stmt) {}
  void run(const MatchFinder::MatchResult &Result) override {
    if (const VarDecl *var = Result.Nodes.getNodeAs<VarDecl>("var")) {
      CheckDerefCallback callback(context);
      // TODO: else node
      if (const auto *compound = dyn_cast<CompoundStmt>(if_stmt.getThen())) {
        for (const Stmt *s : compound->body()) {
          if (const auto *binary_op = dyn_cast<BinaryOperator>(s)) {
            // Stop if we find an assignment to the variable
            if (binary_op->isAssignmentOp()) {
              auto lhs = binary_op->getLHS()->IgnoreParenImpCasts();
              if (const auto *decl_ref = dyn_cast<DeclRefExpr>(lhs)) {
                if (const auto *lhs_var =
                        dyn_cast<VarDecl>(decl_ref->getDecl())) {
                  if (lhs_var == var) {
                    return;
                  }
                }
              }
            }
          }
          MatchFinder finder;
          finder.addMatcher(stmt(hasDescendant(
              memberExpr(hasObjectExpression(ignoringParenImpCasts(
                             declRefExpr(to(varDecl(equalsNode(var)))))))
                  .bind("memberExpr"))),
              &callback);
          finder.addMatcher(stmt(hasDescendant(
              unaryOperator(hasUnaryOperand(ignoringParenImpCasts(
                                declRefExpr(to(varDecl(equalsNode(var)))))),
                            hasOperatorName("*"))
                  .bind("unaryOp"))),
              &callback);
          finder.match(*s, context);
        }
      } else {
        MatchFinder finder;
        finder.addMatcher(stmt(hasDescendant(
            memberExpr(hasObjectExpression(ignoringParenImpCasts(
                          declRefExpr(to(varDecl(equalsNode(var)))))))
                .bind("memberExpr"))),
            &callback);
        finder.addMatcher(stmt(hasDescendant(
            unaryOperator(hasUnaryOperand(ignoringParenImpCasts(
                              declRefExpr(to(varDecl(equalsNode(var)))))),
                          hasOperatorName("*"))
                .bind("unaryOp"))),
            &callback);

        finder.match(*if_stmt.getThen(), context);
      }
    }
  }
};

bool queryNPD(const clang::Stmt *s, clang::ASTContext &context) {
  if (!s) {
    return false;
  }

  if (isa<IfStmt>(s)) {
    const IfStmt *if_stmt = dyn_cast<IfStmt>(s);
    auto if_stmt_node = DynTypedNode::create(*if_stmt);
    MatchFinder finder;
    NullVarCallback callback(context, *if_stmt);
    auto NullMatcher = hasDescendant(integerLiteral(equals(0)));
    finder.addMatcher(ifStmt(hasCondition(binaryOperator(
                          hasOperatorName("=="),
                          hasEitherOperand(ignoringParenImpCasts(
                              declRefExpr(to(varDecl().bind("var"))))),
                          hasEitherOperand(NullMatcher)))),
                      &callback);
    finder.addMatcher(
        ifStmt(hasCondition(unaryOperator(
            hasOperatorName("!"), hasUnaryOperand(ignoringParenImpCasts(
                                      declRefExpr(to(varDecl().bind("var")))))

                ))),
        &callback);

    finder.match(if_stmt_node, context);
  } else {
    for (const Stmt *child : s->children()) {
      queryNPD(child, context);
    }
  }

  return false;
}

void NPDEmitJson(llvm::StringRef filename) {
  auto results = ResultsToJson(NPDResults, "Null Pointer Dereference");
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
