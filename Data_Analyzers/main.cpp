#include <iostream>
#include <thread>
#include <chrono>
#include <curl/curl.h>
#include "Read_Data.h"
#include "acall.h"

using namespace std;
using namespace CSV2JSON;

int main() {
    size_t lastIndex = 0;
    CURL* curl;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        cerr << "CURL init failed" << endl;
        return 1;
    }

    cout << "=== Real-time CSV -> JSON -> LLM ===\n";

    while (true) {
        // Tail new rows from CSVs
        vector<json> newRows = tailMergeCSV(
            "C:/Harshvardhan's_codes/XFlowAI/C++_sniffers/low.csv",
            "C:/Harshvardhan's_codes/XFlowAI/C++_sniffers/flow_app.csv",
            lastIndex
        );

        if (!newRows.empty()) {
            // Feed LLM
            feedLLM(newRows, curl);

            // Optional: persist to NDJSON for later
            writeJSONToFile(newRows, "merged_output.ndjson", false);
        }

        this_thread::sleep_for(chrono::milliseconds(200)); // small delay for real-time polling
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
