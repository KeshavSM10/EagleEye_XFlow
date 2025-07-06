#pragma once
#include<iostream>
#include<winsock2.h>
#include<string>
#include"FlowTracker.h"

class Packet_Handler {
public:
    FlowTracker tracker;
    void handle_packet(u_char* user, const pcap_pkthdr* header, const u_char* packet);
};