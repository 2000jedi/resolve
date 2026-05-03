// src/csv_writer.cpp
#include "csv_writer.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <string>

namespace cpath_baseline {

namespace {

constexpr std::size_t kSnippetMax = 200;
constexpr const char* kHeader =
    "file,line,column,function,kind,snippet\n";

std::string quoteCsvField(const std::string& s) {
    std::string truncated = s.size() > kSnippetMax
                                ? s.substr(0, kSnippetMax)
                                : s;
    std::string out;
    out.reserve(truncated.size() + 2);
    out.push_back('"');
    for (char c : truncated) {
        if (c == '"') out.push_back('"');  // RFC 4180 escape
        // Replace embedded newlines with spaces so each row stays one line.
        if (c == '\n' || c == '\r') out.push_back(' ');
        else out.push_back(c);
    }
    out.push_back('"');
    return out;
}

} // namespace

void appendCsvRow(const std::string& path,
                  const std::string& file,
                  int line,
                  int column,
                  const std::string& function,
                  const std::string& kind,
                  const std::string& snippet) {
    int fd = ::open(path.c_str(),
                    O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;  // silent — analysis must not abort on IO error

    if (::flock(fd, LOCK_EX) != 0) {
        ::close(fd);
        return;
    }

    // Header: write iff the file is empty (race-free under flock).
    struct stat st {};
    if (::fstat(fd, &st) == 0 && st.st_size == 0) {
        (void)::write(fd, kHeader, std::char_traits<char>::length(kHeader));
    }

    char head[256];
    int n = std::snprintf(head, sizeof(head),
                          "%s,%d,%d,%s,%s,",
                          file.c_str(), line, column,
                          function.c_str(), kind.c_str());
    if (n > 0) (void)::write(fd, head, n);
    std::string snippet_quoted = quoteCsvField(snippet);
    (void)::write(fd, snippet_quoted.data(), snippet_quoted.size());
    (void)::write(fd, "\n", 1);

    ::flock(fd, LOCK_UN);
    ::close(fd);
}

} // namespace cpath_baseline
