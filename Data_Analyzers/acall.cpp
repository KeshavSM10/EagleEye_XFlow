#include "acall.h"
#include <iostream>
#include <sstream>
#include <curl/curl.h>
#include "Read_Data.h"
#include <thread>
#include <chrono>

using namespace std;
using namespace CSV2JSON;
using json = nlohmann::json;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    string chunk((char*)contents, size * nmemb);
    stringstream ss(chunk);
    string line;
    while (getline(ss, line)) {
        if (line.empty()) continue;
        try {
            json j = json::parse(line);
            if (j.contains("response")) {
                cout << j["response"].get<string>();
                cout.flush();
            }
        } catch (...) {}
    }
    return size * nmemb;
}

string escape_json_string(const string& input) {
    string escaped = input;
    size_t pos = 0;
    while ((pos = escaped.find('"', pos)) != string::npos) {
        escaped.replace(pos, 1, "\\\"");
        pos += 2;
    }
    pos = 0;
    while ((pos = escaped.find('\n', pos)) != string::npos) {
        escaped.replace(pos, 1, "\\n");
        pos += 2;
    }
    return escaped;
}

// ---------- LLM feed loop ----------
void feedLLM(const vector<json>& newRows, CURL* curl) {
    for (const auto& row : newRows) {
        string escaped = escape_json_string(row.dump());
        string json_request = "{ \"model\": \"llama3.2:1b\", \"prompt\": \"" + escaped + "\" }";

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:11434/api/generate");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_request.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            cerr << "\nCURL error: " << curl_easy_strerror(res) << endl;
        }

        curl_slist_free_all(headers);
    }
}
