#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

// Read_Data.h

namespace CSV2JSON {

using json = nlohmann::json;

// ---------- Utility ----------
std::string trim(const std::string& s);
std::string toUpper(std::string s);
std::vector<std::string> splitCSV(const std::string& line);

// ---------- Normalization ----------
json normalize(const std::string& key, const std::string& rawValue);

// ---------- CSV Parsing ----------
std::vector<json> parseCSV(const std::string& filename);

// ---------- Merge ----------
std::vector<json> mergeByIndex(const std::vector<json>& a,
                               const std::vector<json>& b);

std::vector<json> mergeByKey(const std::vector<json>& a,
                             const std::vector<json>& b,
                             const std::string& keyName);

std::vector<json> tailMergeCSV(
    const std::string& lowFile,
    const std::string& flowFile,
    size_t& lastIndex // keeps track of last read row
);

// Write JSON vector to file
void writeJSONToFile(const std::vector<json>& data,
                     const std::string& filename,
                     bool pretty = true);

} // namespace CSV2JSON
