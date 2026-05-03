// src/search_um_plugin.cpp
//
// Clang plugin: emit one CSV row per malloc() call whose result is
// not null-checked.  Reuses the existing queryBadMalloc analysis
// from src/queryBadMalloc.cpp via a runtime-injected sink, so the
// matcher logic (regex .*malloc.* callee name, climb to LHS, look
// for if(p==0) / if(!p) / etc.) stays in one place.
//
// Mirrors src/Checker.cpp + src/queryBadMalloc.cpp in shape:
// RecursiveASTVisitor iterates FunctionDecls; queryBadMalloc walks
// the body; the consumer routes findings through the sink to CSV
// at end-of-TU.
//
// Loaded as: clang -Xclang -load -Xclang libsearch_um.so \
//                  -Xclang -plugin -Xclang search-um \
//                  -Xclang -plugin-arg-search-um -Xclang out.csv

#include "csv_writer.hpp"
#include "queryBadMalloc.hpp"
#include "llvm_headers.hpp"

#include <clang/Lex/Lexer.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace clang;

// Satisfies the `extern std::string function_name;` declared in
// llvm_headers.hpp.  This .so is loaded standalone (not alongside
// libchecker.so), so nothing else defines it.
std::string function_name;

namespace {

std::string g_outPath;

class FuncVisitor : public RecursiveASTVisitor<FuncVisitor> {
public:
    explicit FuncVisitor(ASTContext &C) : Context(C) {}

    bool VisitFunctionDecl(FunctionDecl *FD) {
        if (!FD->isThisDeclarationADefinition() || !FD->hasBody()) {
            return true;
        }
        const SourceManager &SM = Context.getSourceManager();
        SourceLocation Loc = FD->getLocation();
        if (!Loc.isValid() || SM.isInSystemHeader(Loc)) {
            return true;
        }
        function_name = FD->getNameInfo().getName().getAsString();
        queryBadMalloc(FD->getBody(), Context);
        return true;
    }

private:
    ASTContext &Context;
};

class SearchUmConsumer : public ASTConsumer {
public:
    explicit SearchUmConsumer(ASTContext &C) : Visitor(C) {
        // Route per-finding callbacks straight into the CSV writer.
        setBadMallocSink([](const Stmt *call, ASTContext &ctx) {
            const SourceManager &SM = ctx.getSourceManager();
            SourceLocation loc = call->getBeginLoc();
            if (!loc.isValid()) return;
            std::string filename = SM.getFilename(loc).str();
            if (filename.empty()) return;
            int line = SM.getSpellingLineNumber(loc);
            int col  = SM.getSpellingColumnNumber(loc);
            CharSourceRange range = CharSourceRange::getTokenRange(
                call->getSourceRange());
            std::string snippet = Lexer::getSourceText(
                range, SM, ctx.getLangOpts()).str();
            cpath_baseline::appendCsvRow(
                g_outPath, filename, line, col,
                function_name, "unchecked-malloc", snippet);
        });
    }

    ~SearchUmConsumer() override {
        // Restore default sink so a later TU in the same process
        // (rare for clang -plugin but possible) doesn't dangle.
        setBadMallocSink(nullptr);
    }

    void HandleTranslationUnit(ASTContext &Ctx) override {
        Visitor.TraverseDecl(Ctx.getTranslationUnitDecl());
    }

private:
    FuncVisitor Visitor;
};

class SearchUmAction : public PluginASTAction {
protected:
    std::unique_ptr<ASTConsumer>
    CreateASTConsumer(CompilerInstance &CI, llvm::StringRef) override {
        if (g_outPath.empty()) {
            llvm::errs() << "search-um: missing CSV output path; "
                            "pass via -plugin-arg-search-um <path>\n";
            return nullptr;
        }
        return std::make_unique<SearchUmConsumer>(CI.getASTContext());
    }

    bool ParseArgs(const CompilerInstance &,
                   const std::vector<std::string> &args) override {
        if (args.empty()) {
            llvm::errs() << "search-um: expected one argument "
                            "(CSV output path)\n";
            return false;
        }
        g_outPath = args[0];
        return true;
    }
};

} // namespace

static FrontendPluginRegistry::Add<SearchUmAction>
    Reg("search-um",
        "Emit one CSV row per malloc() call whose result is not null-checked");
