#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

vector<string> split(const string& line, char delimiter) {
    vector<string> tokens;
    stringstream ss(line);
    string token;
    while (getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// smart convert string → number if possible, else keep as string
auto normalize_value = [](const string& key, const string& value) -> json {
    string trimmedKey = key;
    string trimmedValue = value;

    // Trim spaces
    trimmedKey.erase(trimmedKey.find_last_not_of(" \t\r\n") + 1);
    trimmedKey.erase(0, trimmedKey.find_first_not_of(" \t\r\n"));
    trimmedValue.erase(trimmedValue.find_last_not_of(" \t\r\n") + 1);
    trimmedValue.erase(0, trimmedValue.find_first_not_of(" \t\r\n"));

    // Force IPs and MACs to be strings
    if (trimmedKey.find("IP") != string::npos ||
        trimmedKey.find("MAC") != string::npos) {
        return trimmedValue;
    }

    // Try integer
    try {
        size_t idx;
        long long num = stoll(trimmedValue, &idx);
        if (idx == trimmedValue.size()) return num;
    } catch (...) {}

    // Try double
    try {
        size_t idx;
        double d = stod(trimmedValue, &idx);
        if (idx == trimmedValue.size()) return d;
    } catch (...) {}

    // Default to string
    return trimmedValue;
};

vector<json> parseCSV(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error: Could not open " << filename << "\n";
        return {};
    }

    string line;
    vector<string> headers;
    vector<json> rows;

    // Read header row
    if (getline(file, line)) {
        headers = split(line, ',');
    }

    // Read each data row
    while (getline(file, line)) {
        vector<string> values = split(line, ',');
        json obj;

        for (size_t i = 0; i < headers.size(); i++) {
            if (i < values.size() && !values[i].empty()) {
                obj[headers[i]] = normalize_value(headers[i], values[i]); // only non-empty values
            }
        }
        rows.push_back(obj);
    }

    file.close();
    return rows;
}

int main() {
    vector<json> file1_data = parseCSV("C:/Harshvardhan's_codes/XFlowAI/C++_sniffers/low.csv");
    vector<json> file2_data = parseCSV("C:/Harshvardhan's_codes/XFlowAI/C++_sniffers/flow_app.csv");

    json combined = json::array();

    size_t n = min(file1_data.size(), file2_data.size());
    for (size_t i = 0; i < n; i++) {
        json merged = file1_data[i];
        for (auto& [key, value] : file2_data[i].items()) {
            merged[key] = value; // overwrite/add
        }
        combined.push_back(merged);
    }

    // Write to file and also print
    ofstream out("output.json");
    out << combined.dump(4);
    out.close();

    cout << combined.dump(4) << endl;

    return 0;
}
