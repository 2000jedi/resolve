// src/search_malloc_plugin.cpp
//
// Clang plugin: emit one CSV row per literal `malloc(...)` call site.
// Matches the cpath benchmark's `search -p 'malloc($X)'` semantics —
// callee name is exactly `malloc`, no name-regex.  Cast wrappers
// like `(char*)malloc(n)` ARE counted: the matcher binds to the
// inner CallExpr; the cast is a parent node we don't care about.
//
// Mirrors src/Checker.cpp + src/queryBadMalloc.cpp in shape:
// RecursiveASTVisitor iterates FunctionDecls; collectMallocCalls
// recursively walks children for CallExpr; the consumer's
// HandleTranslationUnit emits at end of TU.
//
// Loaded as: clang -Xclang -load -Xclang libsearch_malloc.so \
//                  -Xclang -plugin -Xclang search-malloc \
//                  -Xclang -plugin-arg-search-malloc -Xclang out.csv

#include "csv_writer.hpp"
#include "llvm_headers.hpp"

#include <clang/Lex/Lexer.h>

#include <string>
#include <vector>

using namespace clang;

// Satisfies the `extern std::string function_name;` declared in
// llvm_headers.hpp.  Marked hidden so this symbol does NOT participate
// in cross-.so resolution: when both libsearch_malloc.so and
// libsearch_um.so are loaded into the same clang process (e.g. via
// CFLAGS that names both via `-Xclang -load`), default-visibility
// file-scope globals get merged by the dynamic linker — and on
// process exit BOTH destructors then run on the same memory →
// double-free → SIGABRT in __run_exit_handlers.
__attribute__((visibility("hidden"))) std::string function_name;

namespace {

struct MallocCall {
    std::string filename;
    int line;
    int column;
    std::string function;
    std::string snippet;
};

std::string g_outPath;
std::vector<MallocCall> g_results;

bool isLiteralMalloc(const CallExpr *call) {
    if (const FunctionDecl *callee = call->getDirectCallee()) {
        return callee->getNameAsString() == "malloc";
    }
    return false;
}

/// Recursively walk every Stmt child collecting literal malloc()
/// call sites.  Mirrors the recursion structure of queryBadMalloc().
void collectMallocCalls(const Stmt *s, ASTContext &context) {
    if (!s) return;
    if (const auto *call = dyn_cast<CallExpr>(s)) {
        if (isLiteralMalloc(call)) {
            const SourceManager &SM = context.getSourceManager();
            SourceLocation loc = call->getBeginLoc();
            if (loc.isValid() && !SM.isInSystemHeader(loc)) {
                std::string filename = SM.getFilename(loc).str();
                if (!filename.empty()) {
                    CharSourceRange range = CharSourceRange::getTokenRange(
                        call->getSourceRange());
                    std::string snippet = Lexer::getSourceText(
                        range, SM, context.getLangOpts()).str();
                    g_results.push_back({
                        filename,
                        (int)SM.getSpellingLineNumber(loc),
                        (int)SM.getSpellingColumnNumber(loc),
                        function_name,
                        snippet,
                    });
                }
            }
        }
    }
    for (const auto *child : s->children()) {
        collectMallocCalls(child, context);
    }
}

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
        collectMallocCalls(FD->getBody(), Context);
        return true;
    }

private:
    ASTContext &Context;
};

class SearchMallocConsumer : public ASTConsumer {
public:
    explicit SearchMallocConsumer(ASTContext &C) : Visitor(C) {}

    void HandleTranslationUnit(ASTContext &Ctx) override {
        Visitor.TraverseDecl(Ctx.getTranslationUnitDecl());
        for (const auto &r : g_results) {
            cpath_baseline::appendCsvRow(
                g_outPath, r.filename, r.line, r.column,
                r.function, "malloc-call", r.snippet);
        }
        g_results.clear();
    }

private:
    FuncVisitor Visitor;
};

class SearchMallocAction : public PluginASTAction {
protected:
    std::unique_ptr<ASTConsumer>
    CreateASTConsumer(CompilerInstance &CI, llvm::StringRef) override {
        if (g_outPath.empty()) {
            llvm::errs() << "search-malloc: missing CSV output path; "
                            "pass via -plugin-arg-search-malloc <path>\n";
            return nullptr;
        }
        return std::make_unique<SearchMallocConsumer>(CI.getASTContext());
    }

    bool ParseArgs(const CompilerInstance &,
                   const std::vector<std::string> &args) override {
        if (args.empty()) {
            llvm::errs() << "search-malloc: expected one argument "
                            "(CSV output path)\n";
            return false;
        }
        g_outPath = args[0];
        return true;
    }
};

} // namespace

static FrontendPluginRegistry::Add<SearchMallocAction>
    Reg("search-malloc",
        "Emit one CSV row per literal malloc() call site");
