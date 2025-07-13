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

        file<<"Header lenght,Source MAC,Destination MAC,IP Protocol,Packet Type,Source IP adress,Destination IP adress,DSCP,ECN,IP ID,IP Fragment Offset,Traffic Class,Flow label,Source Port,Destination Port,IPv6 Extension,IPv6 Extension Lenght,Number of IPv6 Extension,IP header lenght,TCP Header Lenght,TTL,Hop Limit,Payload Size,TCP Window Size,UDP header Lenght,Timestamp,Monotonic Timestamp,TCP Flag,SYCK Num,ACK Num,TCP Kind,TCP Options Lenght,Number of Options,ARP Hardware Type,ARP Protocol,ARP Hardware Size,ARP Protocol Size,ARP Opcode val,Sender's mac,Sender's IP,Target mac,Target IP,ICMP Type,ICMP code,Checksum,ICMP Echo,Sequence,IGMP Type,IGMP Max response,IGMP Checksum,Group Addr,Hash Identification\n";
        wrote = true;
    }


    s = s+a;
    i++;
}

void File_logging::add_init(const string& str) {
    add_init(str.c_str());
}

void File_logging::add_init(const char* a) {

    static string s = "";
    static int i = 1;
    static bool wrote = false;

    ofstream file("flow_app.csv",ios::app);

    if(strcmp(a,"end") == 0){

        file<<s;
        s.clear();
        return;
    }


    if(wrote == false){

        file<<"Source IP,Destination IP,Src Port,Dst Port,Protocol_L4,Flow Hash,Flow start,Flow End,Total Bytes from Src IP,TTL MIN, TTL MAX,Total Packets from Src IP,Direction,SYN Flag,RST Flag,ACK Flag,FIN Flag,Total Bidirectional Bytes,Total Conversational Duration,Packet Flow Rate,Bytes Flow Rate,APPLICATION LAYER PROTOCOL,Protocol Sprecific Information,Entropy\n";
        wrote = true;
    }

    s = s+a;
    i++;
}
