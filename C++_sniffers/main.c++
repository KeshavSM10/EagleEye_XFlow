#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <pcap.h>
#include "sniffer.h"
#include "packet_handler.h"
using namespace std;

// void packet_handle(u_char *user_name, const struct pcap_pkthdr *header, const u_char *packet)
// {

//     cout << header->len << endl;

//     for (int i = 0; i < header->caplen; i++)
//     {

//         printf("%02x ", packet[i]);
//     }

//     uint16_t type = packet[12] << 8 | packet[13];

//     if (type == 0x0800)
//     {

//         cout << endl
//              << "IPv4" << endl;

//         in_addr addr_s, addr_d;
//         memcpy(&addr_s, &packet[26], sizeof(in_addr));
//         memcpy(&addr_d, &packet[30], sizeof(in_addr));
//         cout << "source: " << inet_ntoa(addr_s) << " destination: " << inet_ntoa(addr_d) << endl;

//         int a = packet[23];
//         switch (a)
//         {

//         case 6:
//             cout << "TCP" << endl;
//             break;

//         case 17:
//             cout << "UDP" << endl;
//             break;

//         case 1:
//             cout << "ICMP" << endl;
//             break;
//         }
//     }

//     else if (type == 0x86dd)
//     {

//         cout << endl
//              << "IPv6" << endl;

//         string ipv6_s = "";
//         for (int i = 22; i < 38; i += 2)
//         {
//             char block[5];                                        
//             sprintf(block, "%02x%02x", packet[i], packet[i + 1]);
//             ipv6_s += block;
//             if (i != 36)
//                 ipv6_s += ":";
//         }

//         string ipv6_d = "";
//         for (int i = 38; i < 54; i += 2) {
//             char block[5];
//             sprintf(block, "%02x%02x", packet[i], packet[i+1]);
//             ipv6_d += block;
//             if (i != 52) ipv6_d += ":";
//         }
//         cout << "IPv6 source address: " << ipv6_s << "  IPv6 destination adress: " << ipv6_d << endl;

//         int a = packet[69];
//         switch (a)
//         {

//         case 6:
//             cout << "TCP" << endl;
//             break;

//         case 17:
//             cout << "UDP" << endl;
//             break;

//         case 1:
//             cout << "ICMP" << endl;
//             break;
//         }
//     }

//     cout << "-----------------------------------------------------------------------------------------------------------------" << endl;
// }

int main()
{

    sniffer sn;
    sn.sniff_packets();


    // char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_if_t *alldevs, *dev;

    // if (pcap_findalldevs(&alldevs, errbuf) == -1)
    // {

    //     cout << "NO devices" << endl;
    //     exit(1);
    // }

    // dev = alldevs;
    // while (dev != nullptr)
    // {

    //     cout << dev->description << " : " << dev->name << endl;
    //     dev = dev->next;
    // }

    // dev = alldevs;
    // for (int i = 0; i < 4; i++)
    // {

    //     if (dev == nullptr)
    //     {

    //         cout << "No device" << endl;
    //         break;
    //     }
    //     dev = dev->next;
    // }

    // pcap_t *handle = pcap_create(dev->name, errbuf);

    // if (!handle)
    // {

    //     cout << "Clould not make any handle" << endl;
    //     exit(1);
    // }
    // pcap_set_snaplen(handle, BUFSIZ);
    // pcap_set_promisc(handle, 0);
    // pcap_set_timeout(handle, 1000);

    // if (pcap_activate(handle) < 0)
    // {

    //     cout << "Couldn't activate handle";
    //     pcap_close(handle);
    //     pcap_freealldevs(alldevs);
    //     exit(1);
    // }
    // pcap_loop(handle, 20, packet_handle, nullptr);

    // pcap_close(handle);
    // pcap_freealldevs(alldevs);
}