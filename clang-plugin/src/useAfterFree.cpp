#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <regex>
#include <vector>

#include "llvm_headers.hpp"

using namespace clang;
using namespace clang::ast_matchers;

std::vector<CheckResult> UAFSummaries;

namespace {
std::set<const DeclRefExpr *> visitedDeclRefs;

class UAFCallback : public MatchFinder::MatchCallback {
public:
  ASTContext &context;
  const ReturnStmt *result = nullptr;
  UAFCallback(ASTContext &ctx) : context(ctx) {}
  void run(const MatchFinder::MatchResult &Result) override {
    if (const auto *returnStmt =
            Result.Nodes.getNodeAs<ReturnStmt>("returnStmt")) {
      result = returnStmt;
    }
  }
};

const ReturnStmt *isReturned(const ValueDecl *arg, ASTContext &context) {
  MatchFinder finder;
  UAFCallback callback(context);
  const DeclRefExpr *base;

  finder.addMatcher(returnStmt(hasReturnValue(ignoringParenImpCasts(
                                   declRefExpr(to(varDecl(equalsNode(arg)))))))
                        .bind("returnStmt"),
                    &callback);
  finder.matchAST(context);
  return callback.result;
}
} // namespace

void emitUAFDiag(const Stmt *call, ASTContext &context) {
  auto loc = call->getBeginLoc();
  auto filename = context.getSourceManager().getFilename(loc).str();
  if (filename == "") {
    return;
  }
  UAFSummaries.push_back(CheckResult{
      filename,
      function_name,
      (int)context.getSourceManager().getSpellingLineNumber(loc),
  });
}

bool isFree(const CallExpr *call) {
  static const std::regex free_regex(".*free.*");
  if (const FunctionDecl *callee = call->getDirectCallee()) {
    std::string name = callee->getNameAsString();
    if (regex_match(name, free_regex)) {
      return true;
    }
  }
  return false;
}

bool queryUAF(const clang::Stmt *s, clang::ASTContext &context) {
  if (!s)
    return false;
  if (const CallExpr *call = dyn_cast<CallExpr>(s)) {
    if (isFree(call)) {
      if (call->getNumArgs() < 1) {
        return false;
      }
      const Expr *arg = call->getArg(0);
      if (arg)
        arg = arg->IgnoreParenCasts();
      else
        return false;
      if (const DeclRefExpr *declRef = dyn_cast<DeclRefExpr>(arg)) {
        if (visitedDeclRefs.find(declRef) != visitedDeclRefs.end()) {
          return false;
        }
        visitedDeclRefs.insert(declRef);
        const ValueDecl *decl = declRef->getDecl();
        auto hasReturn = isReturned(decl, context);
        if (hasReturn) {
          emitUAFDiag(call, context);
          return true;
        }
      } else {
        return false;
        // The following for debug only
#if 0
        if (isa<MemberExpr>(arg)) {
          // Skip MemberExpr for now
          return false;
        } else {
          arg->dump();
          unsigned DiagID = context.getDiagnostics().getCustomDiagID(
              DiagnosticsEngine::Warning,
              "Unable to analyze use-after-free for non-DeclRefExpr argument");
          context.getDiagnostics().Report(call->getBeginLoc(), DiagID);
        }
#endif
      }
    }
  }
  for (auto child : s->children()) {
    if (queryUAF(child, context)) {
      return true;
    }
  }
  return false;
}

#if 0
bool queryUAF(const clang::Stmt *s, clang::ASTContext &context) {
  class FreeCallback : public MatchFinder::MatchCallback {
  public:
    bool hasReturn = false;
    ASTContext &context;
    FreeCallback(ASTContext &ctx) : context(ctx) {}
    void run(const MatchFinder::MatchResult &Result) override {
      if (this->hasReturn)
        return;
      if (const DeclRefExpr *arg =
      Result.Nodes.getNodeAs<DeclRefExpr>("arg")) {
        if (visitedDeclRefs.find(arg) != visitedDeclRefs.end()) {
          return;
        }
        visitedDeclRefs.insert(arg);
        auto hasReturn = isReturned(arg->getDecl(), context);
        if (hasReturn) {
          auto loc = arg->getBeginLoc();
          auto filename =
          context.getSourceManager().getFilename(loc).str(); if (filename
          == "") {
            return;
          }
          UAFSummaries.push_back(CheckResult{
              filename,
              function_name,
              (int)context.getSourceManager().getSpellingLineNumber(loc),
          });
        }
        this->hasReturn = (!!hasReturn);
      }
    }
  };

  MatchFinder finder;
  FreeCallback callback(context);
  finder.addMatcher(callExpr(callee(functionDecl(hasName("free"))),
                             hasArgument(0, expr().bind("arg"))),
                    &callback);
  finder.matchAST(context);

  return callback.hasReturn;
}
#endif

void UAFEmitJson(llvm::StringRef filename) {
  auto results = ResultsToJson(UAFSummaries, "Use After Free");
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
