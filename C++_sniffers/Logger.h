#pragma once
#include<string>
using namespace std;

class File_logging {

    public:

    void add_to_file(const string& str);
    void add_to_file(const char* c);
    void add_init(const string& str);
    void add_init(const char* c);
};