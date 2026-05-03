// src/queryBadMalloc.hpp
#pragma once

#include "llvm_headers.hpp"

#include <functional>

/// Signature of the user-supplied callback the search_um plugin sets
/// to route results into the CSV writer.  When the callback is null
/// (the default for the legacy `checker` target), findings are
/// appended to the static `mallocResults` vector for later JSONL
/// emit, preserving the existing behaviour.
using BadMallocSink =
    std::function<void(const clang::Stmt* call,
                       clang::ASTContext& context)>;

/// Set the per-finding sink.  Pass `nullptr` to restore the default
/// (static-vector) behaviour used by the legacy `checker` target.
void setBadMallocSink(BadMallocSink sink);

/// Look for malloc calls in the statement tree.  `enclosingFunc` is
/// the FunctionDecl that owns `s` — used to scope the null-check
/// search to that function and to enforce after-malloc ordering.
bool queryBadMalloc(const clang::Stmt *s,
                    clang::ASTContext &context,
                    const clang::FunctionDecl *enclosingFunc);

/// JSONL emit (legacy path).  No-op when the sink override is in use
/// because findings never landed in `mallocResults`.
void badMallocEmitJson(llvm::StringRef filename);
