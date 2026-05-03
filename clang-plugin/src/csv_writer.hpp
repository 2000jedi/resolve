// src/csv_writer.hpp
#pragma once

#include <string>

namespace cpath_baseline {

/// Append one CSV row to `path`.  If `path` is empty when first opened,
/// writes the header `file,line,column,function,kind,snippet\n` first.
/// Each call takes an exclusive flock on the file fd so concurrent
/// clang processes append atomically.
///
/// Fields are written verbatim except `snippet`, which is truncated to
/// 200 chars, wrapped in double-quotes, and has internal `"` doubled
/// per RFC 4180.  No quoting is applied to the other fields — they are
/// expected to be pre-sanitised (paths, identifiers, integers).
void appendCsvRow(const std::string& path,
                  const std::string& file,
                  int line,
                  int column,
                  const std::string& function,
                  const std::string& kind,
                  const std::string& snippet);

} // namespace cpath_baseline
