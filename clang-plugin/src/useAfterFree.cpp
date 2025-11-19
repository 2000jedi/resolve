#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchers.h>
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
  std::vector<const ReturnStmt *> results;
  UAFCallback(ASTContext &ctx) : context(ctx) {}
  void run(const MatchFinder::MatchResult &Result) override {
    if (const auto *returnStmt =
            Result.Nodes.getNodeAs<ReturnStmt>("returnStmt")) {
      results.push_back(returnStmt);
    }
  }
};

std::vector<const ReturnStmt *> isReturned(const ValueDecl *arg,
                                           ASTContext &context) {
  MatchFinder finder;
  UAFCallback callback(context);
  const DeclRefExpr *base;
  std::vector<ReturnStmt> results;

  finder.addMatcher(returnStmt(hasReturnValue(ignoringParenImpCasts(
                                   declRefExpr(to(varDecl(equalsNode(arg)))))))
                        .bind("returnStmt"),
                    &callback);
  finder.matchAST(context);
  return callback.results;
}
} // namespace

bool queryUAF(const clang::Stmt *s, clang::ASTContext &context) {
  class FreeCallback : public MatchFinder::MatchCallback {
  public:
    bool hasReturn = false;
    ASTContext &context;
    FreeCallback(ASTContext &ctx) : context(ctx) {}
    void run(const MatchFinder::MatchResult &Result) override {
      if (const DeclRefExpr *arg = Result.Nodes.getNodeAs<DeclRefExpr>("arg")) {
        if (visitedDeclRefs.find(arg) != visitedDeclRefs.end()) {
          return;
        }
        visitedDeclRefs.insert(arg);
        auto hasReturn = isReturned(arg->getDecl(), context);
        if (!hasReturn.empty()) {
          auto loc = arg->getBeginLoc();
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
        this->hasReturn |= !hasReturn.empty();
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

void UAFEmitJson(void) {
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "  ";
  std::string output = Json::writeString(builder, ResultsToJson(UAFSummaries));

  FILE *f = fopen("uaf_results.json", "w");
  fputs(output.c_str(), f);
}
