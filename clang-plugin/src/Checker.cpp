#include <json/json.h>
#include <vector>

#include "llvm_headers.hpp"
#include "queryBadMalloc.hpp"
#include "queryFPE.hpp"
#include "useAfterFree.hpp"

#define QUERY_BAD_MALLOC
#define QUERY_FPE
#define QUERY_UAF

using namespace clang;
using namespace clang::ast_matchers;

std::string function_name;

namespace {

int positive_div = 0;
int negative_div = 0;

class FuncVisitor : public RecursiveASTVisitor<FuncVisitor> {
public:
  explicit FuncVisitor(ASTContext &C) : Context(C) {}

  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (!FD->isThisDeclarationADefinition() || !FD->hasBody()) {
      return true;
    }

    function_name = FD->getNameInfo().getName().getAsString();

#ifdef QUERY_BAD_MALLOC
    queryBadMalloc(FD->getBody(), Context);
#endif

#ifdef QUERY_FPE
    auto pair = queryFPE(FD->getBody(), Context);
    positive_div += pair.first;
    negative_div += pair.second;
#endif

#ifdef QUERY_UAF
    queryUAF(FD->getBody(), Context);
#endif

    return true;
  }

private:
  ASTContext &Context;
};

class WarnASTConsumer : public ASTConsumer {
public:
  explicit WarnASTConsumer(ASTContext &C) : Visitor(C) {}
  void HandleTranslationUnit(ASTContext &Ctx) override {
    Visitor.TraverseDecl(Ctx.getTranslationUnitDecl());
    if (positive_div + negative_div > 0) {
      llvm::outs() << "Total divisions without zero check: " << positive_div
                   << "\n"
                   << "Total divisions with zero check: " << negative_div
                   << "\n";
    }
#ifdef QUERY_BAD_MALLOC
    badMallocEmitJson();
#endif

#ifdef QUERY_FPE
    FPEEmitJson();
#endif

#ifdef QUERY_UAF
    UAFEmitJson();
#endif
  }

private:
  FuncVisitor Visitor;
};

class WarnAST : public PluginASTAction {
protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 llvm::StringRef) override {
    return std::make_unique<WarnASTConsumer>(CI.getASTContext());
  }

  bool ParseArgs(const CompilerInstance &CI,
                 const std::vector<std::string> &args) override {
    return true;
  }
};

} // namespace

static FrontendPluginRegistry::Add<WarnAST> X("check-ast",
                                              "Check AST for concerns");

Json::Value ResultsToJson(std::vector<CheckResult> &Results) {
  Json::Value results(Json::arrayValue);
  for (const auto &res : Results) {
    Json::Value item;
    item["filename"] = res.filename;
    item["function_name"] = res.function_name;
    item["line_number"] = res.line_number;
    results.append(item);
  }
  return results;
}
