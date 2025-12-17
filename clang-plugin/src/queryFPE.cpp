#include <utility>

#include "llvm_headers.hpp"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchers.h"

using namespace clang;
using namespace clang::ast_matchers;

static std::vector<CheckResult> FPEResults;

class CheckDividentCallback : public MatchFinder::MatchCallback {
public:
  ASTContext &context;
  bool checked;
  CheckDividentCallback(ASTContext &ctx) : context(ctx), checked(false) {}
  void run(const MatchFinder::MatchResult &Result) override {
    if (const auto *ifStmt = Result.Nodes.getNodeAs<IfStmt>("ifStmt")) {
      // unsigned DiagID = context.getDiagnostics().getCustomDiagID(
      //     DiagnosticsEngine::Note, "found ifStmt checking divisor");
      // context.getDiagnostics().Report(ifStmt->getBeginLoc(), DiagID);
      checked = true;
    }
  }
};

bool isCheckedAgainstZero(const Expr *divisor, ASTContext &context) {
  MatchFinder finder;
  CheckDividentCallback callback(context);
  const DeclRefExpr *base;

  while (auto cast = dyn_cast<ImplicitCastExpr>(divisor)) {
    divisor = cast->getSubExpr();
  }

  base = dyn_cast<DeclRefExpr>(divisor);
  if (!base) {
    panic(std::string("Divisor: ") + divisor->getStmtClassName(), context,
          divisor->getBeginLoc());
    return false;
  }
  auto isBase = ignoringParenImpCasts(
      declRefExpr(to(varDecl(equalsNode(base->getDecl())))));
  finder.addMatcher(ifStmt(hasCondition(isBase)).bind("ifStmt"), &callback);
  finder.matchAST(context);
  return callback.checked;
}

/// Class to handle matches for FPE
class DivExprCallback : public MatchFinder::MatchCallback {
public:
  int positive = 0;
  int negative = 0;
  ASTContext &context;
  DivExprCallback(ASTContext &ctx) : context(ctx) {}
  void run(const MatchFinder::MatchResult &Result) override {
    if (const BinaryOperator *div =
            Result.Nodes.getNodeAs<BinaryOperator>("div")) {
      auto rhs = div->getRHS();
      if (!rhs) {
        panic("DivExprCallback: NO RHS", context, div->getBeginLoc());
      }
      bool isChecked = isCheckedAgainstZero(rhs, context);
      if (!isChecked) {
        positive++;
        auto loc = div->getBeginLoc();
        auto filename = context.getSourceManager().getFilename(loc).str();
        if (filename == "") {
          return;
        }
        FPEResults.push_back(CheckResult{
            filename,
            function_name,
            (int)context.getSourceManager().getSpellingLineNumber(loc),
        });
      } else {
        negative++;
      }
    }
  }
};

std::pair<int, int> queryFPE(const clang::Stmt *s, clang::ASTContext &context) {
  auto ConstMatcher = ignoringParenImpCasts(
      anyOf(integerLiteral(), floatLiteral(), unaryExprOrTypeTraitExpr()));

  MatchFinder finder;
  DivExprCallback callback(context);
  finder.addMatcher(
      binaryOperator(hasOperatorName("/"), unless(hasRHS(ConstMatcher)))
          .bind("div"),
      &callback);
  finder.matchAST(context);

  return std::make_pair(callback.positive, callback.negative);
}

void FPEEmitJson(llvm::StringRef filename) {
  auto results = ResultsToJson(FPEResults, "Divide by Zero");
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
