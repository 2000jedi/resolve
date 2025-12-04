#pragma once

#include "llvm_headers.hpp"

/// Look for divisions in the statement tree
/// TODO: check whether the divisor can be zero
bool queryUAF(const clang::Stmt *s, clang::ASTContext &context);

void UAFEmitJson(llvm::StringRef filename);
