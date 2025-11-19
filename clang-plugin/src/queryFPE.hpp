#pragma once

#include <utility>

#include "llvm_headers.hpp"

/// Look for divisions in the statement tree
/// TODO: check whether the divisor can be zero
std::pair<int, int> queryFPE(const clang::Stmt *s, clang::ASTContext &context);

void FPEEmitJson(void);
