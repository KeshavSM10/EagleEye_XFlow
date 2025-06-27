#include "Logger.h"
#include<iostream>
#include<fstream>
#include<string.h>
#include<cstring>
using namespace std;

void File_logging::add_to_file(const string& str) {
    add_to_file(str.c_str());
}

void File_logging::add_to_file(const char* a) {

    static string s = "";
    static int i = 1;
    static bool wrote = false;

    ofstream file("low.csv",ios::app);

    if(strcmp(a,"end") == 0){

        file<<s;
        s.clear();
        return;
    }


    if(wrote == false){

        file<<"Header lenght,Source MAC,Destination MAC,IP Protocol,Packet Type,Source IP adress,Destination IP adress,DSCP,ECN,IP ID,IP Fragment Offset,Traffic Class,Flow label,Source Port,Destination Port,IPv6 Extension,IPv6 Extension Lenght,Number of IPv6 Extension,IP header lenght,TCP Header Lenght,TTL,Hop Limit,Payload Size,TCP Window Size,UDP header Lenght,Timestamp,TCP Flag,SYCK Num,ACK Num,TCP Kind,TCP Options Lenght,Number of Options\n";
        wrote = true;
    }


    s = s+a;
    i++;
}
