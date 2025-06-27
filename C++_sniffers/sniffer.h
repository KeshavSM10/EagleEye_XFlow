#pragma once
#include <pcap.h>
#include "packet_handler.h"

class sniffer {
public:
    void sniff_packets();

private:
    static void static_callback(u_char* user, const pcap_pkthdr* header, const u_char* packet);
    Packet_Handler handler;
};