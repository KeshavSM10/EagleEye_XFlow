#include <pcap.h>
#include <iostream>
#include "packet_handler.h"
#include"sniffer.h"
#include<fstream>
using namespace std;

void sniffer::static_callback(u_char *user, const pcap_pkthdr *header, const u_char *packet)
{
    Packet_Handler *handler = reinterpret_cast<Packet_Handler *>(user);
    handler->handle_packet(user, header, packet);
}

void sniffer::sniff_packets()
{
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {

        cout << "NO devices Found" << endl;
        exit(1);
    }

    dev = alldevs;
    int i = 1;
    while (dev != nullptr)
    {

        cout << i << ": " << dev->description << endl;
        dev = dev->next;
        i++;
    }

    dev = alldevs;
    cout << "Enter device number to select";
    int j;
    cin >> j;

    for (int i = 1; i < j; i++)
    {

        dev = dev->next;
    }

    pcap_t *handle = pcap_create(dev->name, errbuf);
    if (!handle)
    {

        cout << "No handle created" << endl;
        exit(1);
    }

    pcap_set_snaplen(handle, BUFSIZ);
    pcap_set_promisc(handle, 0);
    pcap_set_timeout(handle,1000);

    if (pcap_activate(handle) < 0)
    {

        cout << "Couldn't activate handle" << endl;
        exit(1);
    }

    int dlt = pcap_datalink(handle);
    cout << "Selected Device DLT Number: " << dlt << endl;

    pcap_loop(handle, 200, static_callback, reinterpret_cast<u_char *>(&handler));

    pcap_close(handle);
    pcap_freealldevs(alldevs);
}