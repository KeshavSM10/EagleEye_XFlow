#include "Read_Data.h"
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <cctype>
#include <stdexcept>

//read_data.cpp

using namespace std;

namespace CSV2JSON {

// ---------- Utility: trimming ----------
string trim(const string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// ---------- Utility: uppercase ----------
string toUpper(string s) {
    transform(s.begin(), s.end(), s.begin(),
              [](unsigned char c){ return toupper(c); });
    return s;
}

// ---------- Robust CSV splitter ----------
vector<string> splitCSV(const string& line) {
    vector<string> tokens;
    string token;
    bool inQuotes = false;

    for (size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (c == '\"') {
            inQuotes = !inQuotes;
        } else if (c == ',' && !inQuotes) {
            tokens.push_back(trim(token));
            token.clear();
        } else {
            token.push_back(c);
        }
    }
    tokens.push_back(trim(token));
    return tokens;
}

// ---------- Normalize string values ----------
json normalize(const string& key, const string& rawValue) {
    string value = trim(rawValue);
    string keyUpper = toUpper(trim(key));

    if (value.empty()) return nullptr;

    if (keyUpper.find("IP") != string::npos ||
        keyUpper.find("MAC") != string::npos) {
        return value;
    }

    if (value == "true" || value == "TRUE") return true;
    if (value == "false" || value == "FALSE") return false;
    if (value == "null" || value == "NULL") return nullptr;

    try {
        size_t idx;
        long long num = stoll(value, &idx, 10);
        if (idx == value.size()) return num;
    } catch (...) {}

    try {
        size_t idx;
        double d = stod(value, &idx);
        if (idx == value.size()) return d;
    } catch (...) {}

    return value;
}

// ---------- Parse CSV ----------
vector<json> parseCSV(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Error: Could not open file " + filename);
    }

    string line;
    vector<string> headers;
    vector<json> rows;

    if (getline(file, line)) {
        headers = splitCSV(line);
        for (auto &h : headers) h = trim(h);
    }

   while (getline(file, line)) {
    auto values = splitCSV(line);
    json obj;
    for (size_t i = 0; i < headers.size(); i++) {
        if (i < values.size()) {
            json norm = normalize(headers[i], values[i]);
            if (!norm.is_null()) {      // only insert if not null
                obj[headers[i]] = std::move(norm);
            }
        }
        // else: do nothing, skip missing cell
    }
    rows.push_back(std::move(obj));
}


    return rows;
}

// ---------- Merge by index ----------
vector<json> mergeByIndex(const vector<json>& a, const vector<json>& b) {
    size_t n = min(a.size(), b.size());
    vector<json> merged;
    merged.reserve(n);

    for (size_t i = 0; i < n; i++) {
        json row = a[i];
        for (auto& [key, val] : b[i].items()) {
            row[key] = val;
        }
        merged.push_back(row);
    }
    return merged;
}

// ---------- Merge by key ----------
vector<json> mergeByKey(const vector<json>& a,
                        const vector<json>& b,
                        const string& keyName) {
    unordered_map<string, json> mapA;
    for (const auto& row : a) {
        if (row.contains(keyName))
            mapA[row[keyName].get<string>()] = row;
    }

    vector<json> merged;
    for (const auto& rowB : b) {
        if (rowB.contains(keyName)) {
            string id = rowB[keyName].get<string>();
            json combined = mapA.count(id) ? mapA[id] : json{};
            for (auto& [k, v] : rowB.items()) {
                combined[k] = v;
            }
            merged.push_back(combined);
        }
    }
    return merged;
}

// -----------tail merge csv----------------//
vector<json> tailMergeCSV(const string& lowFile, const string& flowFile, size_t& lastIndex) {
    ifstream fileLow(lowFile);
    ifstream fileFlow(flowFile);
    vector<json> newMerged;
    if (!fileLow.is_open() || !fileFlow.is_open()) throw runtime_error("Cannot open CSVs");

    string lineLow, lineFlow;
    size_t idx = 0;
    while (idx < lastIndex && getline(fileLow, lineLow) && getline(fileFlow, lineFlow)) idx++;

    while (getline(fileLow, lineLow) && getline(fileFlow, lineFlow)) {
        auto rowLow = splitCSV(lineLow);
        auto rowFlow = splitCSV(lineFlow);
        json obj;
        size_t n = min(rowLow.size(), rowFlow.size());
        for (size_t i = 0; i < n; i++) {
            obj["low_" + to_string(i)] = normalize("low_" + to_string(i), rowLow[i]);
            obj["flow_" + to_string(i)] = normalize("flow_" + to_string(i), rowFlow[i]);
        }
        for (auto it = obj.begin(); it != obj.end();)
            if (it.value().is_null()) it = obj.erase(it); else ++it;

        newMerged.push_back(obj);
        idx++;
    }
    lastIndex = idx;
    return newMerged;
}

// ---------- Write JSON ----------
// void writeJSONToFile(const vector<json>& data, const string& filename, bool pretty) {
//     ofstream out(filename);
//     if (!out.is_open()) throw runtime_error("Cannot open file: " + filename);
//     if (pretty) out << json(data).dump(4);
//     else for (const auto& row : data) out << row.dump() << "\n";
//     out.close();
// }


void writeJSONToFile(const vector<json>& data, const string& filename, bool pretty) {
    ofstream out(filename);
    if (!out.is_open()) {
        throw runtime_error("Cannot open file: " + filename);
    }

    if (pretty) {
        out << json(data).dump(4);  // pretty JSON array
    } else {
        // compact NDJSON: one object per line
        for (const auto& row : data) {
            out << row.dump() << "\n";
        }
    }

    out.close();
}

} // namespace CSV2JSON
