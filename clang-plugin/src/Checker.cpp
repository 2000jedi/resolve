#include <fstream>
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

// Expose the function name globally for use in other modules
std::string function_name;

namespace {

int positive_div = 0;
int negative_div = 0;

std::set<std::string> vulnerability_function;

class FuncVisitor : public RecursiveASTVisitor<FuncVisitor> {
public:
  explicit FuncVisitor(ASTContext &C) : Context(C) {}

  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (!FD->isThisDeclarationADefinition() || !FD->hasBody()) {
      return true;
    }

    // If a given vulnerability file is provided, only analyze those functions
    //   defined in .vulnerabilities.[*].affected-function
    if (vulnerability_function.size() > 0) {
      std::string curr_func_name = FD->getNameInfo().getName().getAsString();
      if (vulnerability_function.count(curr_func_name) == 0) {
        return true;
      }
    }

    const SourceManager &SM = Context.getSourceManager();
    SourceLocation Loc = FD->getLocation();
    bool isSystem = SM.isInSystemHeader(Loc);
    bool hasLocation = Loc.isValid();
    if (isSystem || !hasLocation) {
      // llvm::outs() << "Skipping function: "
      //              << FD->getNameInfo().getName().getAsString() << "\n";
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
    // Get the file name
    const SourceManager &SM = Ctx.getSourceManager();
    auto FE = SM.getFileEntryRefForID(SM.getMainFileID());
    llvm::StringRef fileRef = FE->getName();

    // Clear the output file
    std::string fname = fileRef.str() + ".jsonl";
    FILE *f = fopen(fname.c_str(), "w");
    fclose(f);

    Visitor.TraverseDecl(Ctx.getTranslationUnitDecl());
    if (positive_div + negative_div > 0) {
      llvm::outs() << "Total divisions without zero check: " << positive_div
                   << "\n"
                   << "Total divisions with zero check: " << negative_div
                   << "\n";
    }
#ifdef QUERY_BAD_MALLOC
    badMallocEmitJson(fileRef);
#endif

#ifdef QUERY_FPE
    FPEEmitJson(fileRef);
#endif

#ifdef QUERY_UAF
    UAFEmitJson(fileRef);
#endif
  }

private:
  FuncVisitor Visitor;
};

class WarnAST : public PluginASTAction {
  std::vector<std::string> Args;

protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 llvm::StringRef) override {
    if (Args.size() > 0) {
      std::ifstream ifs(Args[0]);
      Json::CharReaderBuilder builder;
      Json::Value obj;
      std::string errs;
      bool ok = Json::parseFromStream(builder, ifs, &obj, &errs);
      if (!ok) {
        llvm::errs() << "Error parsing JSON file: " << errs << "\n";
        exit(1);
      }

      const Json::Value &vuln_funcs = obj["vulnerabilities"];
      if (!vuln_funcs.isArray()) {
        llvm::errs() << "vulnerabilities should be an array\n";
        exit(1);
      }

      for (const auto &func : vuln_funcs) {
        if (func.isMember("affected-function")) {
          vulnerability_function.insert(func["affected-function"].asString());
        } else {
          llvm::errs() << "Each vulnerability must have an affected-function\n";
          exit(1);
        }
      }
    } else {
      vulnerability_function.clear();
    }

    return std::make_unique<WarnASTConsumer>(CI.getASTContext());
  }

  bool ParseArgs(const CompilerInstance &CI,
                 const std::vector<std::string> &args) override {
    for (const auto &a : args) {
      this->Args.push_back(a);
    }
    return true;
  }
};

} // namespace

static FrontendPluginRegistry::Add<WarnAST> X("check-ast",
                                              "Check AST for concerns");

Json::Value ResultsToJson(std::vector<CheckResult> &Results,
                          std::string check) {
  Json::Value result(Json::objectValue);
  Json::Value results(Json::arrayValue);
  for (const auto &res : Results) {
    Json::Value item;
    item["filename"] = res.filename;
    item["function_name"] = res.function_name;
    item["line_number"] = res.line_number;
    results.append(item);
  }
  result[check] = results;
  return result;
}
