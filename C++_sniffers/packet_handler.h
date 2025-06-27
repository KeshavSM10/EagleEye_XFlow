#pragma once
#include<iostream>
#include<winsock2.h>
#include<string>

class Packet_Handler {
public:
    void handle_packet(u_char* user, const pcap_pkthdr* header, const u_char* packet);
};