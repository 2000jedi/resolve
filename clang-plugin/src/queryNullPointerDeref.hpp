#pragma once

#include <utility>

#include "llvm_headers.hpp"

/// Look for divisions in the statement tree
/// TODO: check whether the divisor can be zero
bool queryNPD(const clang::Stmt *s, clang::ASTContext &context);

void NPDEmitJson(llvm::StringRef filename);