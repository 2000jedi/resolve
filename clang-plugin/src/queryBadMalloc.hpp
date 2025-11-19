#pragma once

#include "llvm_headers.hpp"

/// Look for malloc calls in the statement tree
/// If found, look for parent VarDecl and check if it is checked against NULL
bool queryBadMalloc(const clang::Stmt *s, clang::ASTContext &context);

void badMallocEmitJson(void);
