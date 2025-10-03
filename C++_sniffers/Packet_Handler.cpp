#include <pcap.h>
#include <iostream>
#include <winsock2.h>
#include <fstream>
#include "Logger.h"
#include "Packet_Handler.h"
#include <sstream>
#include <iomanip>
#include <string>
#include <ranges>
#include <chrono>
using namespace std;
using namespace std::chrono;

void Packet_Handler::handle_packet(u_char *username, const struct pcap_pkthdr *header, const u_char *packet) {

    cout << "******************************************************************************************************************" << endl;
    cout << "Packet Lenght: " << header->len << endl;

    File_logging l;

    l.add_to_file((to_string(header->caplen) + ",").c_str());
    for (int i = 0; i < header->caplen; i++) {

        printf("%02x ", packet[i]);
    }

    string mac_s = "";
    for (int i = 0; i < 6; i += 1) {
        char block[3];
        sprintf(block, "%02x", packet[i]);
        mac_s += block;
        if (i != 5)
            mac_s += ":";
    }

    l.add_to_file(mac_s.c_str());
    cout << endl
         << mac_s << endl;

    l.add_to_file(",");

    string mac_d = "";

    for (int i = 6; i < 12; i += 1) {
        char block[3];
        sprintf(block, "%02x", packet[i]);
        mac_d += block;
        if (i != 11)
            mac_d += ":";
    }

    l.add_to_file(mac_d.c_str());
    cout << endl
         << mac_d << endl;

    l.add_to_file(",");

    //------------------------------------------------------------------------------------------------------------------------------

    uint16_t type = (packet[12] << 8) | packet[13];
    uint16_t port_source, port_dest;
    uint8_t a = 0;
    uint16_t IP_fragment_flag__offset, traffic_class;

    ostringstream oss;
    oss << "0x" << setfill('0') << setw(4) << hex << uppercase << type;

    //--------------------------------------------------------------------------------------------------------------------------

    in_addr addr_s, addr_d;
    string ipv6_s = "";
    string ipv6_d = "";

    if (type == 0x0800) {

        cout << endl
             << "IP Protocol: IPv4" << endl;
        l.add_to_file(oss.str());

        a = packet[23];

        switch (a) {

        case 1:
            cout << " Packet Type: ICMP" << endl;
            l.add_to_file(",ICMP");
            break;

        case 6:
            cout << " Packet Type: TCP" << endl;
            l.add_to_file(",TCP");
            break;

        case 17:
            cout << " Packet Type: UDP" << endl;
            l.add_to_file(",UDP");
            break;

        default:
            cout << "Unidentified" << endl;
            l.add_to_file((string(",") + to_string(a)).c_str());
        }

        memcpy(&addr_s, &packet[26], sizeof(in_addr));
        memcpy(&addr_d, &packet[30], sizeof(in_addr));

        cout << "Source IP address: " << inet_ntoa(addr_s) << "  Destination IP address: " << inet_ntoa(addr_d) << endl;
        l.add_to_file((string(",") + inet_ntoa(addr_s)).c_str());
        l.add_to_file((string(",") + inet_ntoa(addr_d)).c_str());

        l.add_to_file(",");
        uint8_t dscp = (packet[15] & 0xfc) >> 2;
        l.add_to_file(to_string(dscp));
        // Kind of QoS.

        l.add_to_file(",");
        uint8_t ecn = packet[15] & 0x03;
        l.add_to_file(to_string(ecn));
        // Congestion.

        uint8_t identity = (packet[18] << 8) | packet[19];
        l.add_to_file(",");
        l.add_to_file(to_string(identity));
        //Unique Packet Id for identifying the group of fragments of a single IP datagram (16 bits) .

        IP_fragment_flag__offset = ((packet[20] << 8) | packet[21]) & 0x1fff;
        l.add_to_file(string("," + to_string(IP_fragment_flag__offset) + ",,").c_str());
        // total fgarments or bytes ahead.

        // ((packet[20] << 8) | packet[21]) & 0xd000 would yield specific flag.
    }

    //-----------------------------------------------------------------------------------------------------------------------------

    else if (type == 0x86dd) {

        cout << endl
             << "IP Protocol: IPv6" << endl;

        l.add_to_file(oss.str());

        int next_header = packet[20];
        int offset = 14 + 40;

        while (next_header != 6 && next_header != 17 && offset + 2 < header->len) {

            if (next_header == 58) {

                break;
            }

            int ex_len = packet[offset + 1];
            int jump = (ex_len + 1) * 8;
            offset = offset + jump;
            next_header = packet[offset];

            // in extensions, first 8 bit is next extension or header info, and consequent 8 bit is size of current extension, it is 
            // (extentsion lenght  +  1)*8.
        }

        a = next_header;

        switch (a) {

        case 6:
            cout << " Packet Type: TCP" << endl;
            l.add_to_file(",TCP");
            break;

        case 17:
            cout << " Packet Type: UDP" << endl;
            l.add_to_file(",UDP");
            break;

        case 58:
            cout << " Packet Type: ICMPv6" << endl;
            l.add_to_file(",ICMPv6");
            break;

        case 33:
            cout << " DCCP" << endl;
            l.add_to_file(",DCCP");

        default:
            cout << "UnIdentified" << endl;
            l.add_to_file((string(",") + to_string(a)).c_str());
        }

        for (int i = 22; i < 38; i += 2) {
            char block[5];
            sprintf(block, "%02x%02x", packet[i], packet[i + 1]);
            ipv6_s += block;
            if (i != 36)
                ipv6_s += ":";
        }

        for (int i = 38; i < 54; i += 2) {
            char block[5];
            sprintf(block, "%02x%02x", packet[i], packet[i + 1]);
            ipv6_d += block;
            if (i != 52)
                ipv6_d += ":";
        }

        cout << "IPv6 source address: " << ipv6_s << "  IPv6 destination adress: " << ipv6_d << endl;
        l.add_to_file((string(",") + ipv6_s).c_str());
        l.add_to_file((string(",") + ipv6_d).c_str());

        traffic_class = ((packet[14] & 0x0f) << 4) | (packet[15] >> 4);
        // The Traffic Class field indicates class or priority of IPv6 packet which is similar to Service Field in IPv4 packet.
        // It helps routers to handle the traffic based on the priority of the packet.
        // If congestion occurs on the router then packets with the least priority will be discarded. 

        uint8_t dscp = (traffic_class & 0xfc) >> 2;
        l.add_to_file(",");
        l.add_to_file(to_string(dscp));

        l.add_to_file(",");
        uint8_t ecn = traffic_class & 0x03;
        l.add_to_file(to_string(ecn));

        uint32_t flow_label = ((packet[15] & 0x0f) << 16) | (packet[16] << 8) | packet[17];
        l.add_to_file(",,,");
        l.add_to_file(to_string(traffic_class));
        l.add_to_file(",");
        l.add_to_file(to_string(flow_label));
        //ram and shyam might be talking on say 10 different topics each with different frequency, 
        //and each conversation has different identity, that identity is flow label
    }

    else {

        l.add_to_file(oss.str());
        l.add_to_file(",,,,,,,,,");
    }

    //-------------------------------------------------------------------------------------------------------------------------

    int offset = 0;
    string extension = "";
    int extension_lenght = 0;
    int number_of_enxtensions = 0;

    if (type == 0x0800) {

        offset = (packet[14] & 0x0f) * 4 + 14;

        if (a != 6 && a != 17) {

            l.add_to_file(",,");
        }

        else {
            port_source = (packet[offset] << 8) | packet[offset + 1];
            port_dest = (packet[offset + 2] << 8) | packet[offset + 3];
            cout << port_source << endl;
            l.add_to_file((string(",") + to_string(port_source)).c_str());
            l.add_to_file((string(",") + to_string(port_dest)).c_str());
        }

        l.add_to_file(",,,");
    }

    else if (type == 0x86dd) {

        uint8_t next_header = packet[20];
        offset = 14 + 40;

        while (next_header != 6 && next_header != 17 && next_header != 58 && offset + 2 < header->len) {

            cout << endl
                 << (int)next_header << "-Extension " << extension + "  SecD" << endl;

            extension = extension + to_string(next_header) + "-";

            int ex_len = packet[offset + 1];
            int jump = (ex_len + 1) * 8;

            offset = offset + jump;
            extension_lenght = extension_lenght + jump;
            number_of_enxtensions++;

            next_header = packet[offset];
        }

        if (number_of_enxtensions > 0) {

            offset = offset + (packet[offset + 1] + 1) * 8;
        }

        if (next_header == 6 || next_header == 17) {

            port_source = (packet[offset] << 8) | packet[offset + 1];
            port_dest = (packet[offset + 2] << 8) | packet[offset + 3];
            cout << port_source << endl;
            l.add_to_file((string(",") + to_string(port_source)).c_str());
            l.add_to_file((string(",") + to_string(port_dest)).c_str());
        }

        else {

            l.add_to_file(",,");
        }

        l.add_to_file(",");

        if (extension != "") {
            l.add_to_file(string(extension).c_str());
            cout << endl
                 << "Extension logged--> " << extension << endl;
        }

        l.add_to_file(",");
        l.add_to_file(to_string(extension_lenght));
        l.add_to_file(",");
        l.add_to_file(to_string(number_of_enxtensions));
    }

    else {

        l.add_to_file(",,,,,");
    }

    cout << endl
         << " ----->" << offset << endl;

    //---------------------------------------------------------------------------------------------------------------------------

    if (type == 0x0800 || type == 0x86dd) {

        l.add_to_file(",");
        l.add_to_file(to_string(offset - 14));
    }
    //header lenght.

    else {

        l.add_to_file(",");
    }

    //----------------------------------------------------------------------------------------------------------------------------

    if (a == 6) {
        l.add_to_file(",");
        l.add_to_file(to_string((packet[offset + 12] >> 4) * 4));
    }
    // TCP header lenght.

    else {
        l.add_to_file(",");
    }

    //-----------------------------------------------------------------------------------------------------------------------------

    if (type == 0x0800) {

        l.add_to_file((string(",") + to_string((int)packet[22])).c_str());
        l.add_to_file(",");
    }
    //Time to live.

    else if (type == 0x86dd) {

        l.add_to_file(",");
        l.add_to_file((string(",") + to_string((int)packet[21])).c_str());
    }
    //Hop Limit

    else {
        l.add_to_file(",,");
    }

    //---------------------------------------------------------------------------------------------------------------------------------

    int len = 0;
    if (type == 0x0800) {
        if (a == 6) {

            if (offset + 13 < header->len) {
                len = 14 + (packet[14] & 0x0f) * 4 + (packet[offset + 12] >> 4) * 4;
            }

            l.add_to_file((string(",") + to_string(header->len - len)).c_str());
        }
        //Payload total.

        else if (a == 17) {

            len = 14 + (packet[14] & 0x0f) * 4 + 8;
            l.add_to_file((string(",") + to_string(header->len - len)).c_str());
        }

        else {
            l.add_to_file(",");
        }
    }

    else if (type == 0x86dd) {

        if (a == 6) {

            if (offset + 13 < header->len) {
                len = offset + (packet[offset + 12] >> 4) * 4;
            }
            l.add_to_file((string(",") + to_string(header->len - len)).c_str());
        }

        else if (a == 17) {
            len = offset + 8;
            l.add_to_file((string(",") + to_string(header->len - len)).c_str());
        }

        else {
            l.add_to_file(",");
        }
    }

    else {

        l.add_to_file(",");
    }

    //-------------------------------------------------------------------------------------------------------------------------

    if (a == 6) {

        uint16_t window_size = (packet[offset + 14] << 8) | packet[offset + 15];
        l.add_to_file(",");
        l.add_to_file(to_string(window_size));
        l.add_to_file(",");
    }
    //This field tells the window size of the sending TCP in bytes. 

    else if (a == 17) {

        uint16_t UDP_lenght = (packet[offset + 4] << 8) | (packet[offset + 5]);
        l.add_to_file(",,");
        l.add_to_file(to_string(UDP_lenght));
    }
    // UDP header.

    else {

        l.add_to_file(",,");
    }

    //---------------------------------------------------------------------------------------------------------------------------

    uint64_t time = static_cast<uint64_t>(header->ts.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(header->ts.tv_usec) * 1'000;
    auto mono_n = steady_clock::now();
    auto mono_now = duration_cast<nanoseconds>(mono_n.time_since_epoch());
    l.add_to_file(string("," + to_string(time)).c_str());
    l.add_to_file(string("," + to_string(mono_now.count())).c_str());

    //TIme stamp.

    //-------------------------------------------------------------------------------------------------------------------------------

    if (a == 6) {

        l.add_to_file((string(",") + string("0x") + to_string((int)packet[offset + 13])).c_str());
    }

    else {

        l.add_to_file(",");
    }
    // TCP Flags.

    //-------------------------------------------------------------------------------------------------------------------------------

    if (type == 0x86dd) {

        if (a == 6) {

            uint32_t SYCK = (packet[offset + 4] << 24) | (packet[offset + 5] << 16) | (packet[offset + 6] << 8) | packet[offset + 7];
            string syck = to_string(SYCK);
            cout << endl
                 << "syck:" << syck;
            l.add_to_file(("," + syck).c_str());

            uint32_t ACK = (packet[62] << 24) | (packet[63] << 16) | (packet[64] << 8) | packet[65];
            string ack = to_string(ACK);
            cout << endl
                 << "ack:" << ack << endl;
            l.add_to_file(("," + ack).c_str());
        }

        else {

            l.add_to_file(",,");
        }
    }

    else if (type == 0x0800) {

        if (a == 6) {

            uint32_t SYCK = (packet[offset + 4] << 24) | (packet[offset + 5] << 16) | (packet[offset + 6] << 8) | packet[offset + 7];
            string syck = to_string(SYCK);
            cout << endl
                 << "syck:" << syck;
            l.add_to_file(("," + syck).c_str());

            uint32_t ACK = (packet[offset + 8] << 24) | (packet[offset + 9] << 16) | (packet[offset + 10] << 8) | packet[offset + 11];
            string ack = to_string(ACK);
            cout << endl
                 << "ack:" << ack << endl;
            l.add_to_file(("," + ack).c_str());
        }

        else {

            l.add_to_file(",,");
        }
    }

    else {

        l.add_to_file(",,");
    }

    // ACK and SYCK Numbers

    //---------------------------------------------------------------------------------------------------------------------------

    // TCP Dissection, Info, Kind, Options all.....

    // TCP Options (Kind): 0-End, 1-NOP, 2-MSS, 3-WSopt, 4-SACK-Permitted, 5-SACK, 8-TSopt,
    // 9-PAD, 14-AltChk, 15-Skeeter, 16-Bubba, 17-TrafficRateExp, 18-TrafficRate, 19-MC-TCP, 20-RVSP, 21-QS, 
    // 22-UserTimeout, 23-TCP-AO, 24-CC, 25-CC.NEW, 26-CC.ECHO, 27-AltChkData, 28-TCP-Auth, 29-MultipathTCP, 
    // 30-FastOpen, 69-Experimental


    if (((packet[offset + 12] >> 4) * 4) > 20 && a == 6) {

        int options_pointer = offset + 20;
        string kind_list = "";
        int Number_of_options = 0;
        int Lenght_of_options = ((packet[offset + 12] >> 4) * 4) - 20;

        while (packet[options_pointer] != 0) {

            kind_list = kind_list + to_string(packet[options_pointer]) + ":";

            if (packet[options_pointer] == 1) {

                Number_of_options++;
                options_pointer = options_pointer + 1;
                if ((options_pointer >= (packet[offset + 12] >> 4) * 4) + offset) {

                    break;
                }
                continue;
            }

            int lenght = packet[options_pointer + 1];

            if (lenght <= 2) {

                break;
            }

            options_pointer = options_pointer + lenght;
            Number_of_options++;

            if ((options_pointer >= (packet[offset + 12] >> 4) * 4) + offset) {

                break;
            }
        }

        l.add_to_file(string(",") + kind_list + string(",") + to_string(Lenght_of_options) + string(",") + to_string(Number_of_options).c_str());
    }

    else {

        l.add_to_file(",,,");
    }

    //----------------------------------------------------------------------------------------------------------------------------

    if (type == 0x0806) {

        uint16_t hard_t = (packet[14] << 8) | packet[15];
        ostringstream har_t;
        har_t << "0x" << setfill('0') << setw(4) << hex << uppercase << hard_t;
        cout << har_t.str() << endl;
        l.add_to_file((string(",") + har_t.str()).c_str());

        uint16_t proto_t = (packet[16] << 8) | packet[17];
        ostringstream prt;
        prt << "0x" << setfill('0') << setw(4) << hex << uppercase << proto_t;
        cout << prt.str() << endl;
        l.add_to_file((string(",") + prt.str()).c_str());

        uint8_t hardware_size = packet[18];
        l.add_to_file((string(",") + to_string(hardware_size)).c_str());

        uint8_t protocol_size = packet[19];
        l.add_to_file((string(",") + to_string(protocol_size)).c_str());

        uint16_t opcode_val = (packet[20] << 8) | packet[21];
        l.add_to_file((string(",") + to_string(opcode_val)).c_str());

        string sender_mac = "";
        for (int i = 22; i < 28; i += 1) {
            char block[2];
            sprintf(block, "%02x", packet[i]);
            sender_mac += block;
            if (i != 5)
                sender_mac += ":";
        }
        l.add_to_file(",");
        l.add_to_file(sender_mac);

        in_addr senders_addr;
        memcpy(&senders_addr, &packet[28], sizeof(in_addr));
        l.add_to_file((string(",") + inet_ntoa(senders_addr)).c_str());

        string target_mac = "";
        for (int i = 32; i < 38; i += 1) {
            char block[2];
            sprintf(block, "%02x", packet[i]);
            target_mac += block;
            cout << "-->" << target_mac << endl;
            if (i != 5)
                target_mac += ":";
        }
        l.add_to_file(",");
        l.add_to_file(target_mac.c_str());

        in_addr target_addr;
        memcpy(&target_addr, &packet[38], sizeof(in_addr));
        l.add_to_file((string(",") + inet_ntoa(target_addr)).c_str());
    }

    else {

        l.add_to_file(",,,,,,,,,");
    }

    //----------------------------------------------------------------------------------------------------------------------------

    if (type == 0x0800 && a == 1) {

        int icmp_offset = 14 + (packet[14] & 0x0f) * 4;

        uint8_t type = packet[icmp_offset];
        l.add_to_file((string(",") + to_string(type)).c_str());

        uint8_t code = packet[icmp_offset + 1];
        l.add_to_file((string(",") + to_string(code)).c_str());

        uint16_t checksum_t = (packet[icmp_offset + 2] << 8) | packet[icmp_offset + 3];
        ostringstream checksum;
        checksum << "0x" << setfill('0') << setw(4) << hex << uppercase << checksum_t;
        l.add_to_file(",");
        l.add_to_file(checksum.str());

        uint16_t echo = (packet[icmp_offset + 4] << 8) | packet[icmp_offset + 5];
        ostringstream echo_t;
        echo_t << "0x" << setfill('0') << setw(4) << hex << uppercase << echo;
        l.add_to_file(",");
        l.add_to_file(echo_t.str());

        uint16_t Sequence = (packet[icmp_offset + 6] << 8) | packet[icmp_offset + 7];
        l.add_to_file((string(",") + to_string(Sequence)).c_str());
    }

    else if (type == 0x86dd && a == 58) {

        int icmp_offset = offset;

        uint8_t type = packet[icmp_offset];
        l.add_to_file((string(",") + to_string(type)).c_str());

        uint8_t code = packet[icmp_offset + 1];
        l.add_to_file((string(",") + to_string(code)).c_str());

        uint16_t checksum_t = (packet[icmp_offset + 2] << 8) | packet[icmp_offset + 3];
        ostringstream checksum;
        checksum << "0x" << setfill('0') << setw(4) << hex << uppercase << checksum_t;
        l.add_to_file(",");
        l.add_to_file(checksum.str());

        uint16_t echo = (packet[icmp_offset + 4] << 8) | packet[icmp_offset + 5];
        ostringstream echo_t;
        echo_t << "0x" << setfill('0') << setw(4) << hex << uppercase << echo;
        l.add_to_file(",");
        l.add_to_file(echo_t.str());

        uint16_t Sequence = (packet[icmp_offset + 6] << 8) | packet[icmp_offset + 7];
        l.add_to_file((string(",") + to_string(Sequence)).c_str());
    }

    else {

        l.add_to_file(",,,,,");
    }

    //--------------------------------------------------------------------------------------------------------------------------

    if (a == 2 && type == 0x0800) {

        int igmp_offset = 14 + (packet[14] & 0x0f) * 4;

        uint8_t type_x = packet[igmp_offset];
        ostringstream type_x_i;
        type_x_i << "0x" << setfill('0') << setw(2) << hex << uppercase << type_x;
        l.add_to_file(",");
        l.add_to_file(type_x_i.str());

        uint8_t max_response = packet[igmp_offset + 1];
        l.add_to_file((string(",") + to_string(max_response)).c_str());

        uint16_t checksum_t = (packet[igmp_offset + 2] << 8) | packet[igmp_offset + 3];
        ostringstream checksum;
        checksum << "0x" << setfill('0') << setw(4) << hex << uppercase << checksum_t;
        l.add_to_file(",");
        l.add_to_file(checksum.str());

        in_addr group_addr;
        memcpy(&group_addr, &packet[igmp_offset + 4], sizeof(in_addr));
        l.add_to_file((string(",") + inet_ntoa(group_addr)).c_str());
    }

    else {

        l.add_to_file(",,,,");
    }

    //--------------------------------------------------------------------------------------------------------------------------

    int app_layer_offset = 0;
    string L7_protocol;
    int dst_port = port_dest;
    int src_port = port_source;
    int protocol = a;
    string method = "";

    string Logging = "";
    string Protocol_SUMM = "";
    string Entrp = "";

    string APP_LAYER_PROTOCOL = "";

    if (a == 6) {
        app_layer_offset = offset + ((packet[offset + 12] & 0xf0) >> 4) * 4;
    }
    else if (a == 17) {
        app_layer_offset = offset + 8;
    }

    int payload = header->len - app_layer_offset;

    if (payload >= 3 && packet[app_layer_offset] == 0x16 && packet[app_layer_offset + 1] == 0x03 && packet[app_layer_offset + 2] <= 0x03) {
        L7_protocol = "TLS Handshake";
    }

    if (payload <= 0) {}

    else {
        switch (a) {
        case 6:
            for (int i = 0; i < payload; i++) {
                if (packet[app_layer_offset + i] <= 127) {
                    method += packet[app_layer_offset + i];
                }
            }

            if (dst_port == 80 || src_port == 80 || dst_port == 8080 || src_port == 8080 || dst_port == 8000 || src_port == 8000) {
                string payload_str(reinterpret_cast<const char *>(packet + app_layer_offset), payload);

                if (payload_str.starts_with("GET") || payload_str.starts_with("POST") || payload_str.starts_with("PUT") ||
                    payload_str.starts_with("DELETE") || payload_str.starts_with("HEAD") || payload_str.starts_with("HTTP/")) {
                    APP_LAYER_PROTOCOL = "HTTP";

                    size_t space_pos = payload_str.find(' ');
                    string http_method = (space_pos != string::npos) ? payload_str.substr(0, space_pos) : "UNKNOWN";

                    size_t uri_start = space_pos + 1;
                    size_t uri_end = payload_str.find(' ', uri_start);
                    string uri = (uri_end != string::npos) ? payload_str.substr(uri_start, uri_end - uri_start) : "/";

                    string host = "Unknown";
                    size_t host_pos = payload_str.find("Host:");
                    if (host_pos != string::npos) {
                        size_t host_start = host_pos + 5;
                        while (host_start < payload_str.length() && payload_str[host_start] == ' ')
                            host_start++;
                        size_t host_end = payload_str.find("\r\n", host_start);
                        if (host_end == string::npos)
                            host_end = payload_str.find("\n", host_start);
                        host = (host_end != string::npos) ? payload_str.substr(host_start, host_end - host_start) : payload_str.substr(host_start);
                    }

                    string user_agent = "";
                    size_t ua_pos = payload_str.find("User-Agent:");
                    if (ua_pos != string::npos) {
                        size_t ua_start = ua_pos + 11;
                        while (ua_start < payload_str.length() && payload_str[ua_start] == ' ')
                            ua_start++;
                        size_t ua_end = payload_str.find("\r\n", ua_start);
                        if (ua_end == string::npos)
                            ua_end = payload_str.find("\n", ua_start);
                        user_agent = (ua_end != string::npos) ? payload_str.substr(ua_start, ua_end - ua_start) : payload_str.substr(ua_start);
                    }

                    string content_type = "";
                    size_t ct_pos = payload_str.find("Content-Type:");
                    if (ct_pos != string::npos) {
                        size_t ct_start = ct_pos + 13;
                        while (ct_start < payload_str.length() && payload_str[ct_start] == ' ')
                            ct_start++;
                        size_t ct_end = payload_str.find("\r\n", ct_start);
                        if (ct_end == string::npos)
                            ct_end = payload_str.find("\n", ct_start);
                        content_type = (ct_end != string::npos) ? payload_str.substr(ct_start, ct_end - ct_start) : payload_str.substr(ct_start);
                    }

                    Protocol_SUMM = "HTTP Request - Method: " + http_method + " | URL: " + uri + " | Host: " + host;
                    if (!user_agent.empty())
                        Protocol_SUMM += " | User-Agent: " + user_agent;
                    if (!content_type.empty())
                        Protocol_SUMM += " | Content-Type: " + content_type;

                    Entrp = http_method + uri + host;
                    if (!user_agent.empty()) {
                        Entrp += user_agent;
                    }
                    if (!content_type.empty()) {
                        Entrp += content_type;
                    }
                }
            }

            else if (dst_port == 22 || src_port == 22){
                if (method.starts_with("SSH-")){
                    APP_LAYER_PROTOCOL = "SSH";
                    size_t version_end = method.find('\r');
                    if (version_end == string::npos)
                        version_end = method.find('\n');
                    string version = (version_end != string::npos) ? method.substr(0, version_end) : method.substr(0, 50);

                    string ssh_version = "";
                    string software_version = "";
                    size_t dash_pos = version.find('-', 4);
                    if (dash_pos != string::npos) {
                        ssh_version = version.substr(4, dash_pos - 4);
                        software_version = version.substr(dash_pos + 1);
                    }

                    Protocol_SUMM = "SSH Connection - Version: " + version + " | SSH Ver: " + ssh_version + " | Software: " + software_version;

                    Entrp = version + ssh_version + software_version;
                }
            }

            else if (dst_port == 21 || src_port == 21) {
                APP_LAYER_PROTOCOL = "FTP";
                size_t line_end = method.find('\r');
                if (line_end == string::npos)
                    line_end = method.find('\n');
                string ftp_command = (line_end != string::npos) ? method.substr(0, line_end) : method.substr(0, 100);

                string ftp_cmd = "";
                string ftp_args = "";
                size_t space_pos = ftp_command.find(' ');
                if (space_pos != string::npos) {
                    ftp_cmd = ftp_command.substr(0, space_pos);
                    ftp_args = ftp_command.substr(space_pos + 1);
                }
                else {
                    ftp_cmd = ftp_command;
                }

                Protocol_SUMM = "FTP Command: " + ftp_command + " | CMD: " + ftp_cmd + " | Args: " + ftp_args;

                Entrp = ftp_cmd + ftp_args + to_string(dst_port) + to_string(src_port);
            }

            else if (dst_port == 25 || src_port == 25 || dst_port == 587 || src_port == 587) {
                if (method.starts_with("HELO") || method.starts_with("EHLO")) {
                    APP_LAYER_PROTOCOL = "SMTP";
                    size_t space_pos = method.find(' ');
                    string smtp_command = (space_pos != string::npos) ? method.substr(0, space_pos) : method;
                    string smtp_domain = "";
                    if (space_pos != string::npos) {
                        size_t domain_start = space_pos + 1;
                        size_t domain_end = method.find('\r', domain_start);
                        if (domain_end == string::npos)
                            domain_end = method.find('\n', domain_start);
                        smtp_domain = (domain_end != string::npos) ? method.substr(domain_start, domain_end - domain_start) : method.substr(domain_start);
                    }
                    Protocol_SUMM = "SMTP Greeting - Command: " + smtp_command + " | Domain: " + smtp_domain;

                    Entrp = smtp_command + smtp_domain + to_string(dst_port);
                }
                else if (method.starts_with("MAIL FROM:")) {
                    APP_LAYER_PROTOCOL = "SMTP";
                    size_t from_start = method.find("MAIL FROM:");
                    string from_email = method.substr(from_start + 10);
                    size_t line_end = from_email.find('\r');
                    if (line_end != string::npos)
                        from_email = from_email.substr(0, line_end);

                    string email_domain = "";
                    size_t at_pos = from_email.find('@');
                    if (at_pos != string::npos) {
                        email_domain = from_email.substr(at_pos + 1);
                    }

                    Protocol_SUMM = "SMTP Mail - From: " + from_email + " | Domain: " + email_domain;

                    Entrp = from_email + email_domain + "MAILFROM";
                }
            }

            else if (dst_port == 110 || src_port == 110) {
                if (method.starts_with("+OK")) {
                    APP_LAYER_PROTOCOL = "POP3";
                    size_t line_end = method.find('\r');
                    string pop3_response = (line_end != string::npos) ? method.substr(0, line_end) : method.substr(0, 100);

                    string pop3_msg = "";
                    size_t space_pos = pop3_response.find(' ');
                    if (space_pos != string::npos) {
                        pop3_msg = pop3_response.substr(space_pos + 1);
                    }

                    Protocol_SUMM = "POP3 Response: " + pop3_response + " | Message: " + pop3_msg;

                    Entrp = pop3_response + pop3_msg + to_string(dst_port);
                }
            }

            else if (dst_port == 143 || src_port == 143) {
                if (method.starts_with("* OK")){
                    APP_LAYER_PROTOCOL = "IMAP";
                    size_t line_end = method.find('\r');
                    string imap_response = (line_end != string::npos) ? method.substr(0, line_end) : method.substr(0, 100);

                    string imap_caps = "";
                    size_t caps_pos = imap_response.find("[CAPABILITY");
                    if (caps_pos != string::npos) {
                        size_t caps_end = imap_response.find(']', caps_pos);
                        if (caps_end != string::npos) {
                            imap_caps = imap_response.substr(caps_pos, caps_end - caps_pos + 1);
                        }
                    }

                    Protocol_SUMM = "IMAP Response: " + imap_response + " | Capabilities: " + imap_caps;

                    Entrp = imap_response + imap_caps + to_string(dst_port);
                }
            }

            else if (dst_port == 443 || src_port == 443) {
                if (L7_protocol == "TLS Handshake") {
                    APP_LAYER_PROTOCOL = "HTTPS";
                    uint8_t tls_version_major = packet[app_layer_offset + 1];
                    uint8_t tls_version_minor = packet[app_layer_offset + 2];
                    uint8_t handshake_type = packet[app_layer_offset + 5];

                    string handshake_type_str = "";
                    string ja3_fingerprint = "";
                    string sni_hostname = "";

                    switch (handshake_type) {
                    case 1: 
                        handshake_type_str = "Client Hello";

                        try {
                            int pos = app_layer_offset + 9; 

                            pos += 34;

                            uint8_t session_id_len = packet[pos++];
                            pos += session_id_len;

                            uint16_t cipher_suites_len = (packet[pos] << 8) | packet[pos + 1];
                            pos += 2;

                            vector<uint16_t> cipher_suites;
                            for (int i = 0; i < cipher_suites_len; i += 2) {
                                uint16_t cipher = (packet[pos + i] << 8) | packet[pos + i + 1];
                                cipher_suites.push_back(cipher);
                            }
                            pos += cipher_suites_len;

                            uint8_t compression_len = packet[pos++];
                            pos += compression_len;

                            uint16_t extensions_len = (packet[pos] << 8) | packet[pos + 1];
                            pos += 2;

                            vector<uint16_t> extensions;
                            vector<uint16_t> elliptic_curves;
                            vector<uint8_t> ec_point_formats;

                            int ext_end = pos + extensions_len;
                            while (pos < ext_end) {
                                uint16_t ext_type = (packet[pos] << 8) | packet[pos + 1];
                                uint16_t ext_len = (packet[pos + 2] << 8) | packet[pos + 3];
                                pos += 4;

                                extensions.push_back(ext_type);

                                if (ext_type == 0 && sni_hostname.empty()) {
                                    int sni_pos = pos + 2; 
                                    uint8_t name_type = packet[sni_pos++];
                                    uint16_t name_len = (packet[sni_pos] << 8) | packet[sni_pos + 1];
                                    sni_pos += 2;

                                    if (name_type == 0) { 
                                        sni_hostname = string(reinterpret_cast<const char *>(&packet[sni_pos]), name_len);
                                    }
                                }

                                else if (ext_type == 10) {
                                    uint16_t list_len = (packet[pos] << 8) | packet[pos + 1];
                                    int curve_pos = pos + 2;
                                    for (int i = 0; i < list_len; i += 2) {
                                        uint16_t curve = (packet[curve_pos + i] << 8) | packet[curve_pos + i + 1];
                                        elliptic_curves.push_back(curve);
                                    }
                                }

                                else if (ext_type == 11) {
                                    uint8_t formats_len = packet[pos];
                                    for (int i = 0; i < formats_len; i++) {
                                        ec_point_formats.push_back(packet[pos + 1 + i]);
                                    }
                                }

                                pos += ext_len;
                            }

                            string ja3_string = to_string((tls_version_major << 8) | tls_version_minor) + ",";

                            for (size_t i = 0; i < cipher_suites.size(); i++) {
                                ja3_string += to_string(cipher_suites[i]);
                                if (i < cipher_suites.size() - 1)
                                    ja3_string += "-";
                            }
                            ja3_string += ",";

                            for (size_t i = 0; i < extensions.size(); i++) {
                                ja3_string += to_string(extensions[i]);
                                if (i < extensions.size() - 1)
                                    ja3_string += "-";
                            }
                            ja3_string += ",";

                            for (size_t i = 0; i < elliptic_curves.size(); i++) {
                                ja3_string += to_string(elliptic_curves[i]);
                                if (i < elliptic_curves.size() - 1)
                                    ja3_string += "-";
                            }
                            ja3_string += ",";

                            for (size_t i = 0; i < ec_point_formats.size(); i++) {
                                ja3_string += to_string(ec_point_formats[i]);
                                if (i < ec_point_formats.size() - 1)
                                    ja3_string += "-";
                            }

                            hash<string> hasher;
                            size_t hash_value = hasher(ja3_string);
                            stringstream ss;
                            ss << hex << hash_value;
                            ja3_fingerprint = ss.str();
                        }
                        catch (...){}

                        break;

                    case 2:
                        handshake_type_str = "Server Hello";
                        break;
                    case 11:
                        handshake_type_str = "Certificate";
                        break;
                    case 12:
                        handshake_type_str = "Server Key Exchange";
                        break;
                    case 14:
                        handshake_type_str = "Server Hello Done";
                        break;
                    case 16:
                        handshake_type_str = "Client Key Exchange";
                        break;
                    default:
                        handshake_type_str = "Type " + to_string(handshake_type);
                        break;
                    }

                    Protocol_SUMM = "HTTPS TLS Handshake - Version: " + to_string(tls_version_major) + "." + to_string(tls_version_minor) + " | Type: " + handshake_type_str;

                    if (!sni_hostname.empty()) {
                        Protocol_SUMM += " | SNI: " + sni_hostname;
                    }

                    if (!ja3_fingerprint.empty()) {
                        Protocol_SUMM += " | JA3: " + ja3_fingerprint.substr(0, 16) + "...";
                    }

                    Entrp = to_string(tls_version_major) + to_string(tls_version_minor) + to_string(handshake_type) + "TLS";
                }
                else {
                    APP_LAYER_PROTOCOL = "Encrypted";
                    Protocol_SUMM = "Encrypted HTTPS Traffic";
                    Entrp = "ENCRYPTED" + to_string(dst_port) + to_string(payload);
                }
            }

            else if (dst_port == 23 || src_port == 23)
            {
                APP_LAYER_PROTOCOL = "TELNET";
                string telnet_data = "";
                bool has_telnet_commands = false;

                for (int i = 0; i < payload && i < 100; i++) {
                    if (packet[app_layer_offset + i] == 0xFF) {
                        has_telnet_commands = true;
                        break;
                    }

                    if (packet[app_layer_offset + i] >= 32 && packet[app_layer_offset + i] <= 126) {
                        telnet_data += (char)packet[app_layer_offset + i];
                    }
                }

                Protocol_SUMM = "TELNET Session - Data: " + telnet_data.substr(0, 50) +
                                " | Has Commands: " + (has_telnet_commands ? "Yes" : "No");

                Entrp = telnet_data + to_string(has_telnet_commands) + to_string(dst_port);
            }

            else {
                APP_LAYER_PROTOCOL = "UNIDENTIFIED";
            }

            break;

        case 17:
        {
            for (int i = 0; i < payload && i < 200; i++)
            {
                if (i >= payload)
                    break;

                if (packet[app_layer_offset + i] <= 127) {
                    char c = packet[app_layer_offset + i];
                    method += c;
                }
            }

            if (dst_port == 53 || src_port == 53) {
                if (payload >= 12) {
                    APP_LAYER_PROTOCOL = "DNS";

                    uint16_t transaction_id = (packet[app_layer_offset] << 8) | packet[app_layer_offset + 1];
                    uint16_t flags = (packet[app_layer_offset + 2] << 8) | packet[app_layer_offset + 3];
                    uint16_t questions = (packet[app_layer_offset + 4] << 8) | packet[app_layer_offset + 5];
                    uint16_t answers = (packet[app_layer_offset + 6] << 8) | packet[app_layer_offset + 7];

                    bool is_query = (flags & 0x8000) == 0;
                    uint8_t opcode = (flags >> 11) & 0x0F;

                    string domain_name = "";
                    if (questions > 0 && payload > 12) {
                        int name_offset = app_layer_offset + 12;
                        while (name_offset < app_layer_offset + payload) {
                            uint8_t len = packet[name_offset];
                            if (len == 0)
                                break;
                            if (len > 63)
                                break;

                            if (!domain_name.empty())
                                domain_name += ".";
                            for (int i = 0; i < len && name_offset + 1 + i < app_layer_offset + payload; i++) {
                                domain_name += (char)packet[name_offset + 1 + i];
                            }
                            name_offset += len + 1;
                        }
                    }

                    Protocol_SUMM = "DNS " + string(is_query ? "Query" : "Response") + " - Domain: " + domain_name +
                                    " | Questions: " + to_string(questions) + " | Answers: " + to_string(answers) +
                                    " | TxID: " + to_string(transaction_id);

                    Entrp = domain_name + to_string(transaction_id) + to_string(opcode) + to_string(questions) + to_string(answers);
                }
            }

            else if (dst_port == 123 || src_port == 123) {
                if (packet[app_layer_offset] == 0x1b) {
                    APP_LAYER_PROTOCOL = "NTP";
                    uint8_t version = (packet[app_layer_offset] >> 3) & 0x7;
                    uint8_t mode = packet[app_layer_offset] & 0x7;
                    uint8_t stratum = packet[app_layer_offset + 1];

                    string mode_str = "";
                    switch (mode) {
                    case 1:
                        mode_str = "Symmetric Active";
                        break;
                    case 2:
                        mode_str = "Symmetric Passive";
                        break;
                    case 3:
                        mode_str = "Client";
                        break;
                    case 4:
                        mode_str = "Server";
                        break;
                    case 5:
                        mode_str = "Broadcast";
                        break;
                    default:
                        mode_str = "Unknown(" + to_string(mode) + ")";
                        break;
                    }

                    Protocol_SUMM = "NTP Packet - Version: " + to_string(version) + " | Mode: " + mode_str +
                                    " | Stratum: " + to_string(stratum);

                    Entrp = to_string(version) + to_string(mode) + to_string(stratum) + mode_str;
                }
            }

            else if (dst_port == 161 || src_port == 161) {
                if (packet[app_layer_offset] == 0x30) {
                    APP_LAYER_PROTOCOL = "SNMP";
                    Protocol_SUMM = "SNMP Request - ASN.1 BER Encoded Message";

                    Entrp = method.substr(0, min(50, (int)method.length()));
                }
            }

            else if (dst_port == 67 || src_port == 67 || dst_port == 68 || src_port == 68) {
                if (packet[app_layer_offset] == 0x01 || packet[app_layer_offset] == 0x02) {
                    APP_LAYER_PROTOCOL = "DHCP";
                    uint8_t msg_type = packet[app_layer_offset];
                    uint8_t hw_type = packet[app_layer_offset + 1];
                    uint32_t transaction_id = (packet[app_layer_offset + 4] << 24) |
                                              (packet[app_layer_offset + 5] << 16) |
                                              (packet[app_layer_offset + 6] << 8) |
                                              packet[app_layer_offset + 7];

                    string client_mac = "";
                    for (int i = 0; i < 6; i++) {
                        if (i > 0)
                            client_mac += ":";
                        char hex[3];
                        sprintf(hex, "%02x", packet[app_layer_offset + 28 + i]);
                        client_mac += hex;
                    }

                    Protocol_SUMM = "DHCP " + string(msg_type == 0x01 ? "Request" : "Reply") +
                                    " - Client MAC: " + client_mac + " | Transaction ID: 0x" +
                                    to_string(transaction_id);

                    Entrp = client_mac + to_string(transaction_id) + to_string(msg_type) + to_string(hw_type);
                }
            }

            else if (dst_port == 443 || src_port == 443) {
                if (payload >= 13) {
                    uint8_t first_byte = packet[app_layer_offset];

                    if ((first_byte & 0x80) != 0) {
                        APP_LAYER_PROTOCOL = "QUIC";

                        uint32_t version = (packet[app_layer_offset + 1] << 24) |
                                           (packet[app_layer_offset + 2] << 16) |
                                           (packet[app_layer_offset + 3] << 8) |
                                           packet[app_layer_offset + 4];

                        uint8_t packet_type = (first_byte & 0x30) >> 4;
                        bool fixed_bit = (first_byte & 0x40) != 0;
                        uint8_t type_specific = first_byte & 0x0F;

                        string packet_type_str = "";
                        switch (packet_type) {
                        case 0:
                            packet_type_str = "Initial";
                            break;
                        case 1:
                            packet_type_str = "0-RTT";
                            break;
                        case 2:
                            packet_type_str = "Handshake";
                            break;
                        case 3:
                            packet_type_str = "Retry";
                            break;
                        default:
                            packet_type_str = "Unknown";
                            break;
                        }

                        uint8_t dcid_len = packet[app_layer_offset + 5];
                        string dest_conn_id = "";
                        if (dcid_len > 0 && dcid_len <= 20) {
                            for (int i = 0; i < dcid_len && i < 20; i++) {
                                char hex[3];
                                sprintf(hex, "%02x", packet[app_layer_offset + 6 + i]);
                                dest_conn_id += hex;
                            }
                        }

                        int scid_offset = app_layer_offset + 6 + dcid_len;
                        uint8_t scid_len = 0;
                        string src_conn_id = "";
                        if (scid_offset < app_layer_offset + payload) {
                            scid_len = packet[scid_offset];
                            if (scid_len > 0 && scid_len <= 20) {
                                for (int i = 0; i < scid_len && i < 20; i++) {
                                    char hex[3];
                                    sprintf(hex, "%02x", packet[scid_offset + 1 + i]);
                                    src_conn_id += hex;
                                }
                            }
                        }

                        string token_info = "";
                        if (packet_type == 0) {
                            int token_offset = scid_offset + 1 + scid_len;
                            if (token_offset < app_layer_offset + payload) {
                                uint8_t token_len = packet[token_offset];
                                token_info = " | Token Length: " + to_string(token_len);
                            }
                        }

                        uint8_t pn_length = (type_specific & 0x03) + 1;

                        string version_str = "";
                        if (version == 0x00000001)
                            version_str = "v1";
                        else if (version == 0x00000000)
                            version_str = "Version Negotiation";
                        else if ((version & 0x0F0F0F0F) == 0x0A0A0A0A)
                            version_str = "Draft Version";
                        else
                            version_str = "0x" + to_string(version);

                        Protocol_SUMM = "QUIC " + packet_type_str + " - Version: " + version_str +
                                        " | DCID: " + dest_conn_id + " | SCID: " + src_conn_id +
                                        " | PN Length: " + to_string(pn_length) + token_info;

                        Entrp = dest_conn_id + src_conn_id + to_string(version) + packet_type_str + to_string(pn_length);
                    }
                    else {
                        APP_LAYER_PROTOCOL = "QUIC";

                        bool fixed_bit = (first_byte & 0x40) != 0;
                        bool spin_bit = (first_byte & 0x20) != 0;
                        uint8_t key_phase = (first_byte & 0x04) >> 2;
                        uint8_t pn_length = (first_byte & 0x03) + 1;

                        string dest_conn_id = "";
                        int dcid_len = min(8, payload - 1 - pn_length);
                        for (int i = 0; i < dcid_len; i++) {
                            char hex[3];
                            sprintf(hex, "%02x", packet[app_layer_offset + 1 + i]);
                            dest_conn_id += hex;
                        }

                        string packet_number = "";
                        int pn_offset = app_layer_offset + 1 + dcid_len;
                        for (int i = 0; i < pn_length && pn_offset + i < app_layer_offset + payload; i++) {
                            char hex[3];
                            sprintf(hex, "%02x", packet[pn_offset + i]);
                            packet_number += hex;
                        }

                        Protocol_SUMM = "QUIC Data Packet - DCID: " + dest_conn_id +
                                        " | Encrypted PN: " + packet_number +
                                        " | Spin Bit: " + (spin_bit ? "1" : "0") +
                                        " | Key Phase: " + to_string(key_phase) +
                                        " | PN Length: " + to_string(pn_length);

                        Entrp = dest_conn_id + packet_number + to_string(key_phase) + to_string(pn_length);
                    }
                }
                else {
                    APP_LAYER_PROTOCOL = "HTTPS/QUIC";
                    Protocol_SUMM = "Encrypted UDP Traffic on Port 443 - Insufficient Data";

                    Entrp = method.substr(0, min(20, (int)method.length()));
                }
            }

            else if (dst_port == 5060 || src_port == 5060) {
                if (method.starts_with("INVITE") || method.starts_with("ACK") || method.starts_with("BYE") ||
                    method.starts_with("CANCEL") || method.starts_with("REGISTER")) {
                    APP_LAYER_PROTOCOL = "SIP";

                    size_t space_pos = method.find(' ');
                    string sip_method = (space_pos != string::npos) ? method.substr(0, space_pos) : method;
                    string sip_uri = "";
                    if (space_pos != string::npos) {
                        size_t uri_start = space_pos + 1;
                        size_t uri_end = method.find(' ', uri_start);
                        if (uri_end == string::npos)
                            uri_end = method.find('\r', uri_start);
                        sip_uri = (uri_end != string::npos) ? method.substr(uri_start, uri_end - uri_start) : method.substr(uri_start);
                    }

                    string call_id = "";
                    size_t call_id_pos = method.find("Call-ID:");
                    if (call_id_pos != string::npos) {
                        size_t id_start = call_id_pos + 8;
                        while (id_start < method.length() && method[id_start] == ' ')
                            id_start++;
                        size_t id_end = method.find('\r', id_start);
                        if (id_end == string::npos)
                            id_end = method.find('\n', id_start);
                        call_id = (id_end != string::npos) ? method.substr(id_start, id_end - id_start) : method.substr(id_start);
                    }

                    Protocol_SUMM = "SIP " + sip_method + " - URI: " + sip_uri;
                    if (!call_id.empty())
                        Protocol_SUMM += " | Call-ID: " + call_id;

                    Entrp = sip_method + sip_uri + call_id;
                }
            }

            else if (dst_port == 69 || src_port == 69) {
                if (payload >= 4) {
                    uint16_t opcode = (packet[app_layer_offset] << 8) | packet[app_layer_offset + 1];
                    if (opcode >= 1 && opcode <= 5) {
                        APP_LAYER_PROTOCOL = "TFTP";

                        string opcode_str = "";
                        string filename = "";

                        switch (opcode) {
                        case 1:
                            opcode_str = "Read Request";
                            break;
                        case 2:
                            opcode_str = "Write Request";
                            break;
                        case 3:
                            opcode_str = "Data";
                            break;
                        case 4:
                            opcode_str = "ACK";
                            break;
                        case 5:
                            opcode_str = "Error";
                            break;
                        }

                        if (opcode == 1 || opcode == 2) {
                            int name_start = app_layer_offset + 2;
                            for (int i = 0; i < 50 && name_start + i < app_layer_offset + payload; i++) {
                                if (packet[name_start + i] == 0)
                                    break;
                                filename += (char)packet[name_start + i];
                            }
                        }

                        Protocol_SUMM = "TFTP " + opcode_str + " - File: " + filename;

                        Entrp = filename + to_string(opcode) + opcode_str;
                    }
                }
            }

            else if (dst_port == 514 || src_port == 514) {
                APP_LAYER_PROTOCOL = "SYSLOG";

                string syslog_msg = "";
                for (int i = 0; i < min(100, payload); i++) {
                    if (packet[app_layer_offset + i] >= 32 && packet[app_layer_offset + i] <= 126) {
                        syslog_msg += (char)packet[app_layer_offset + i];
                    }
                }

                string priority = "";
                if (syslog_msg.length() > 0 && syslog_msg[0] == '<') {
                    size_t end_pos = syslog_msg.find('>');
                    if (end_pos != string::npos) {
                        priority = syslog_msg.substr(1, end_pos - 1);
                    }
                }

                Protocol_SUMM = "SYSLOG Message - Priority: " + priority + " | Message: " + syslog_msg.substr(0, 50);

                Entrp = priority + syslog_msg.substr(0, 50);
            }

            else if (dst_port == 162 || src_port == 162) {
                if (packet[app_layer_offset] == 0x30) {
                    APP_LAYER_PROTOCOL = "SNMP_TRAP";
                    Protocol_SUMM = "SNMP Trap - ASN.1 BER Encoded Message";

                    Entrp = method.substr(0, min(50, (int)method.length()));
                }
            }

            else
            {
                if (packet[app_layer_offset] == 0x80) {
                    APP_LAYER_PROTOCOL = "RTP";
                    uint8_t version = (packet[app_layer_offset] >> 6) & 0x3;
                    uint8_t payload_type = packet[app_layer_offset + 1] & 0x7F;
                    uint16_t seq_num = (packet[app_layer_offset + 2] << 8) | packet[app_layer_offset + 3];
                    uint32_t timestamp = (packet[app_layer_offset + 4] << 24) | (packet[app_layer_offset + 5] << 16) |
                                         (packet[app_layer_offset + 6] << 8) | packet[app_layer_offset + 7];

                    string payload_type_str = "";
                    switch (payload_type) {
                    case 0:
                        payload_type_str = "PCMU";
                        break;
                    case 8:
                        payload_type_str = "PCMA";
                        break;
                    case 96:
                        payload_type_str = "Dynamic";
                        break;
                    default:
                        payload_type_str = "Type " + to_string(payload_type);
                        break;
                    }

                    Protocol_SUMM = "RTP Stream - Payload: " + payload_type_str + " | Sequence: " +
                                    to_string(seq_num) + " | Timestamp: " + to_string(timestamp);

                    Entrp = payload_type_str + to_string(seq_num) + to_string(timestamp) + to_string(version);
                }
            }

            break;
        }
        }
    }

    Logging += APP_LAYER_PROTOCOL;
    Logging += ",";
    Logging += Protocol_SUMM;
    Logging += ",";

    double entr = tracker.calculate_Entropy(Entrp);
    Logging += to_string(entr);

    Logging += ",";

    cout << endl
         << "###############################################################################################" << endl;
    cout << APP_LAYER_PROTOCOL << " : " << Protocol_SUMM <<" : entr :"<<entr<< endl;

//-------------------------------------------------------------------------------------------------------------------------

    bool ACK = false;
    bool RST = false;
    bool SYN = false;
    bool FIN = false;

    if (a == 6) {

        uint8_t tcp_flags = packet[offset + 13];

        ACK = tcp_flags & 0x10;
        RST = tcp_flags & 0x04;
        SYN = tcp_flags & 0x02;
        FIN = tcp_flags & 0x01;
    }

    string srcip = (type == 0x86dd) ? ipv6_s : inet_ntoa(addr_s);
    string dstip = (type == 0x86dd) ? ipv6_d : inet_ntoa(addr_d);

    tracker.processPacket(srcip, dstip, port_source, port_dest, a, mono_now, mono_now, header->len, 1, (uint8_t)packet[21], (uint8_t)packet[22], ACK, SYN, RST, FIN, "");

    tracker.updateMeta(srcip, mono_now, header->len);

    auto t = steady_clock::now().time_since_epoch();
    auto t_n = duration_cast<nanoseconds>(t);
    cout << " time now :" << t_n << endl;

    tracker.expireFlow(t_n);

//---------------------------------------------------------------------------------------------------------------------------

    tracker.log_to_csv(srcip, dstip, port_source, port_dest, a, Logging);

    FlowStructHasher f_H;
    FlowIdentifier f_I;
    f_I.SrcIP = srcip;
    f_I.DstIP = dstip;
    f_I.SrcPort = port_source;
    f_I.DstPort = port_dest;
    f_I.Protocol = a;


    size_t hash = f_H(f_I);
    l.add_to_file(",");
    l.add_to_file(to_string(hash));

    l.add_to_file("\n");
    l.add_to_file("end");
}
