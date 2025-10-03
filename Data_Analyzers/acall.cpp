#include <iostream>
#include <string>
#include <sstream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;

// Callback to print streamed LLM output immediately
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
        } catch (...) {
            // ignore partial/incomplete JSON
        }
    }
    return size * nmemb;
}

// Escape quotes and newlines for JSON string
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

int main() {
    CURL* curl;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        cerr << "CURL initialization failed!" << endl;
        return 1;
    }

    cout << "=== LLM Interactive Session ===\n";
    cout << "Instructions:\n";
    cout << "  - Paste multi-line JSON packets or prompts\n";
    cout << "  - Type 'END' on a new line to submit\n";
    cout << "  - Type 'exit' to quit\n\n";

    while (true) {
        cout << "Paste input:\n";
        string line, user_input;
        while (getline(cin, line)) {
            if (line == "END") break;
            if (line == "exit") return 0;
            user_input += line + "\n";
        }

        // Skip empty input
        if (user_input.empty()) continue;

        // Always wrap input in prompt so LLM responds
        string escaped_input = escape_json_string(user_input);
        string json_request = "{ \"model\": \"llama3.2:1b\", \"prompt\": \"" + escaped_input + "\" }";

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
        } else {
            cout << "\n--- Response complete ---\n";
        }

        curl_slist_free_all(headers);
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
