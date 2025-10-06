#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include<curl/curl.h>

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
std::string escape_json_string(const std::string& input);

void feedLLM(const std::vector<nlohmann::json>& newRows, CURL* curl);