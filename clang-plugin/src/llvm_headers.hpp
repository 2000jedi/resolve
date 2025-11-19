#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/Diagnostic.h>
#include <clang/Basic/SourceLocation.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/FrontendPluginRegistry.h>
#include <json/json.h>
#include <llvm-18/llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>

void panic(std::string msg, clang::ASTContext &context,
           clang::SourceLocation loc);

struct CheckResult {
  std::string filename;
  std::string function_name;
  int line_number = 0;
};

Json::Value ResultsToJson(std::vector<CheckResult> &Results);
extern std::string function_name;
