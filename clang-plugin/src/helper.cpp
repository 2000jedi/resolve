#include "llvm_headers.hpp"

#include <fstream>

void panic(std::string msg, clang::ASTContext &context,
           clang::SourceLocation loc) {
  std::ofstream ofs("panic.log", std::ios::app);
  ofs << msg << "\n";
  ofs.close();
}
