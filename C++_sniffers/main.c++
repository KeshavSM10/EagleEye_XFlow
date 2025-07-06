#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <pcap.h>
#include "sniffer.h"
#include "packet_handler.h"
using namespace std;


int main()
{
    sniffer sn;
    sn.sniff_packets();
}

