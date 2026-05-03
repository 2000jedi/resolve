#include <json/json.h>
#include <string>
#include <vector>

#include "llvm_headers.hpp"

std::vector<Json::Value> ResultsToJson(std::vector<CheckResult> &Results,
                                       std::string check) {
  std::vector<Json::Value> results;
  for (const auto &res : Results) {
    Json::Value item;
    item["vulnerability_type"] = check;
    item["filename"] = res.filename;
    item["function_name"] = res.function_name;
    item["line_number"] = res.line_number;
    results.push_back(item);
  }
  return results;
}
