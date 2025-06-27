#include <pcap.h>
#include <iostream>
#include <winsock2.h>
#include<fstream>
#include "Logger.h"
#include "Packet_Handler.h"
#include<sstream>
#include<iomanip>
#include<string>
using namespace std;

void Packet_Handler::handle_packet(u_char *username, const struct pcap_pkthdr *header, const u_char *packet)
{

    cout << "******************************************************************************************************************" << endl;
    cout << "Packet Lenght: " << header->len << endl;

    File_logging l;

    l.add_to_file((to_string(header->caplen)+",").c_str());
    for (int i = 0; i < header->caplen; i++)
    {

        printf("%02x ", packet[i]);
    }

    string mac_s = "";
    for (int i = 0; i < 6; i += 1)
        {
            char block[2];
            sprintf(block, "%02x", packet[i]);
            mac_s += block;
            if (i != 5)
                mac_s += ":";
        }
    l.add_to_file(mac_s.c_str());
    cout<<endl<<mac_s<<endl;

    l.add_to_file(",");

    string mac_d = "";
    for (int i = 6; i < 12; i += 1)
        {
            char block[2];
            sprintf(block, "%02x", packet[i]);
            mac_d += block;
            if (i != 11)
                mac_d += ":";
        }
    l.add_to_file(mac_d.c_str());
    cout<<endl<<mac_d<<endl;

    l.add_to_file(",");

    //------------------------------------------------------------------------------------------------------------------------------

    uint16_t type = (packet[12] << 8) | packet[13];
    uint16_t port_source, port_dest;
    int a = 0;
    uint16_t IP_fragment_flag__offset, traffic_class;

    ostringstream oss;
    oss<<"0x"<<setfill('0')<<setw(4)<<hex<<uppercase<<type;

    //--------------------------------------------------------------------------------------------------------------------------

    if (type == 0x0800)
    {

        cout << endl<< "IP Protocol: IPv4" << endl;
        l.add_to_file(oss.str());

        a = packet[23];

        switch (a)
        {

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
            cout<<"Unidentified"<<endl;
            l.add_to_file((string(",")+to_string(a)).c_str());
        }

        in_addr addr_s, addr_d;

        memcpy(&addr_s, &packet[26], sizeof(in_addr));
        memcpy(&addr_d, &packet[30], sizeof(in_addr));

        cout << "Source IP address: " << inet_ntoa(addr_s) << "  Destination IP address: " << inet_ntoa(addr_d) << endl;
        l.add_to_file((string(",") + inet_ntoa(addr_s)).c_str());
        l.add_to_file((string(",") + inet_ntoa(addr_d)).c_str());

        l.add_to_file(",");
        uint8_t dscp = (packet[15]&0xfc)>>2;
        l.add_to_file(to_string(dscp));

        l.add_to_file(",");
        uint8_t ecn = packet[15]&0x03;
        l.add_to_file(to_string(ecn));

        uint8_t identity = (packet[18]<<8)|packet[19];
        l.add_to_file(",");
        l.add_to_file(to_string(identity));

        IP_fragment_flag__offset = ((packet[20]<<8)|packet[21]) & 0x1fff;
        l.add_to_file(string("," + to_string(IP_fragment_flag__offset)+",,").c_str());
    }

    //-----------------------------------------------------------------------------------------------------------------------------

    else if (type == 0x86dd)
    {

        cout<<endl << "IP Protocol: IPv6" << endl;

        l.add_to_file(oss.str());

        int next_header = packet[20];
        int offset = 14+40;

        while(next_header != 6 && next_header != 17 && offset+2<header->len){

            if(next_header == 58){

                break;
            }
            int ex_len = packet[offset+1];
            int jump = (ex_len+1)*8;
            offset = offset+jump;
            next_header = packet[offset];
        }

        a = next_header;

        switch (a)
        {

        case 6:
            cout << " Packet Type: TCP" << endl;
            l.add_to_file(",TCP");
            break;

        case 17:
            cout << " Packet Type: UDP" << endl;
            l.add_to_file(",UDP");
            break;

        case 58:
            cout<<" Packet Type: ICMPv6" << endl;
            l.add_to_file(",ICMPv6");
            break;

        case 33:
            cout<<" DCCP"<<endl;
            l.add_to_file(",DCCP");

        default:
            cout<<"UnIdentified"<<endl;
            l.add_to_file((string(",")+to_string(a)).c_str());
        }

        string ipv6_s = "";
        for (int i = 22; i < 38; i += 2)
        {
            char block[5];
            sprintf(block, "%02x%02x", packet[i], packet[i + 1]);
            ipv6_s += block;
            if (i != 36)
                ipv6_s += ":";
        }

        string ipv6_d = "";
        for (int i = 38; i < 54; i += 2)
        {
            char block[5];
            sprintf(block, "%02x%02x", packet[i], packet[i + 1]);
            ipv6_d += block;
            if (i != 52)
                ipv6_d += ":";
        }
        cout << "IPv6 source address: " << ipv6_s << "  IPv6 destination adress: " << ipv6_d << endl;
        l.add_to_file((string(",") + ipv6_s).c_str());
        l.add_to_file((string(",") + ipv6_d).c_str());

        traffic_class = ((packet[14] & 0x0f)<<4)|(packet[15]>>4);

        uint8_t dscp = (traffic_class & 0xfc)>>2;
        l.add_to_file(",");
        l.add_to_file(to_string(dscp));

        l.add_to_file(",");
        uint8_t ecn = traffic_class & 0x03;
        l.add_to_file(to_string(ecn));

        uint32_t flow_label = ((packet[15] & 0x0f)<<16)|(packet[16]<<8)|packet[17];
        l.add_to_file(",,,");
        l.add_to_file(to_string(traffic_class));
        l.add_to_file(",");
        l.add_to_file(to_string(flow_label));
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

    if(type == 0x0800){

        offset = (packet[14] & 0x0f)*4 + 14;

        if(a != 6 && a != 17){

        l.add_to_file(",,");
        }

        else {
            port_source = (packet[offset]<<8)|packet[offset+1];
            port_dest = (packet[offset+2]<<8)|packet[offset+3];
            cout<<port_source<<endl;
            l.add_to_file((string(",")+to_string(port_source)).c_str());
            l.add_to_file((string(",")+to_string(port_dest)).c_str());
        }

        l.add_to_file(",,,");
    }

    else if(type == 0x86dd){

        uint8_t next_header = packet[20];
        offset = 14+40;

        while(next_header != 6 && next_header != 17 && offset+2<header->len){

            cout<<endl<<(int)next_header<<"-Extension "<<extension+"  SecD"<<endl;
            
            if(next_header == 58){
                
                break;
            }
            
            if(next_header == 131){
                
                extension = extension+to_string(next_header)+":";
                break;
            }
            
            if(next_header == 255){
                
                break;
            }
            extension = extension+to_string(next_header)+":";

            int ex_len = packet[offset+1];
            int jump = (ex_len+1)*8;
            offset = offset+jump;
            extension_lenght = extension_lenght+jump;
            number_of_enxtensions++;
            next_header = packet[offset];
        }

        if(next_header == 6 || next_header == 17){

            port_source = (packet[offset]<<8)|packet[offset+1];
            port_dest = (packet[offset+2]<<8)|packet[offset+3];
            cout<<port_source<<endl;
            l.add_to_file((string(",")+to_string(port_source)).c_str());
            l.add_to_file((string(",")+to_string(port_dest)).c_str());
        }

        else {

            l.add_to_file(",,");
        }

        l.add_to_file(",");

        if(extension != ""){
            l.add_to_file(string(extension).c_str());
            cout<<endl<<"Extension logged--> " <<extension<<endl;
        }

        l.add_to_file(",");
        l.add_to_file(to_string(extension_lenght));
        l.add_to_file(",");
        l.add_to_file(to_string(number_of_enxtensions));
    }

    else{

        l.add_to_file(",,,,,");
    }

    //---------------------------------------------------------------------------------------------------------------------------

    if(type == 0x0800 || type == 0x86dd){
        
            l.add_to_file(",");
            l.add_to_file(to_string(offset-14));
        }

    else {

        l.add_to_file(",");
    }

    //----------------------------------------------------------------------------------------------------------------------------

    if(a == 6){
        l.add_to_file(",");
        l.add_to_file(to_string((packet[offset + 12] >> 4)*4));
    }

    else {
        l.add_to_file(",");
    }
    
    //-----------------------------------------------------------------------------------------------------------------------------

    if(type == 0x0800){

        l.add_to_file((string(",")+to_string((int)packet[22])).c_str());
        l.add_to_file(",");
    }

    else if(type == 0x86dd){

        l.add_to_file(",");
        l.add_to_file((string(",")+to_string((int)packet[21])).c_str());
    }

    else{
        l.add_to_file(",,");
    }

    //---------------------------------------------------------------------------------------------------------------------------------

    int len = 0;
    if(type == 0x0800){
        if(a == 6){

            if (offset + 13 < header->len){
                len = 14+ (packet[14]&0x0f)*4 + (packet[offset + 12] >> 4)*4;
            }

            l.add_to_file((string(",")+to_string(header->len - len)).c_str());
        }
        
        else if(a == 17){

            len = 14+ (packet[14]&0x0f)*4+8;
            l.add_to_file((string(",")+to_string(header->len - len)).c_str());
        }

        else{
            l.add_to_file(",");
        }
    }


    else if(type == 0x86dd){

        if(a == 6){

            if (offset + 13 < header->len){
                len = offset + (packet[offset + 12] >> 4)*4;
            }
            l.add_to_file((string(",")+to_string(header->len - len)).c_str());
        }
        
        else if(a == 17){
            len = offset+8;
            l.add_to_file((string(",")+to_string(header->len - len)).c_str());
        }

        else{
            l.add_to_file(",");
        }
    }

    else{

        l.add_to_file(",");
    }

    //-------------------------------------------------------------------------------------------------------------------------

    if(a == 6){

        uint16_t window_size = (packet[offset+14]<<8) | packet[offset+15];
        l.add_to_file(",");
        l.add_to_file(to_string(window_size));
        l.add_to_file(",");
    }

    else if(a == 17){

        uint16_t UDP_lenght = (packet[offset+4]<<8)|(packet[offset+5]);
        l.add_to_file(",,");
        l.add_to_file(to_string(UDP_lenght));
    }

    else {

        l.add_to_file(",,");
    }

    //---------------------------------------------------------------------------------------------------------------------------

    
    l.add_to_file((","+to_string(header->ts.tv_sec)).c_str());

    //-------------------------------------------------------------------------------------------------------------------------------

    if(a == 6){

        if(type == 0x0800) l.add_to_file((string(",")+string("0x")+to_string((int)packet[offset+13])).c_str());
        else if(type == 0x86dd) l.add_to_file((string(",")+string("0x")+to_string((int)packet[offset+13])).c_str());
        else l.add_to_file(",");
    }

    //-------------------------------------------------------------------------------------------------------------------------------


    if(type == 0x86dd){

        if(a == 6){

            uint32_t SYCK = (packet[offset+4]<<24)|(packet[offset+5]<<16)|(packet[offset+6]<<8)|packet[offset+7];
            string syck = to_string(SYCK);
            cout<<endl<<"syck:"<<syck;
            l.add_to_file((","+syck).c_str());

            uint32_t ACK = (packet[62]<<24)|(packet[63]<<16)|(packet[64]<<8)|packet[65];
            string ack = to_string(ACK);
            cout<<endl<<"ack:"<<ack<<endl;
            l.add_to_file((","+ack).c_str());
        }
    }

    else if(type == 0x0800){

        if(a == 6){

            uint32_t SYCK = (packet[offset+4]<<24)|(packet[offset+5]<<16)|(packet[offset+6]<<8)|packet[offset+7];
            string syck = to_string(SYCK);
            cout<<endl<<"syck:"<<syck;
            l.add_to_file((","+syck).c_str());

            uint32_t ACK = (packet[offset+8]<<24)|(packet[offset+9]<<16)|(packet[offset+10]<<8)|packet[offset+11];
            string ack = to_string(ACK);
            cout<<endl<<"ack:"<<ack<<endl;
            l.add_to_file((","+ack).c_str());
        }
    }

    else{

        l.add_to_file(",,");
    }

    //---------------------------------------------------------------------------------------------------------------------------

    if(((packet[offset+12]>>4)*4)>20){

        int options_pointer = offset+20;
        string kind_list = "";
        int Number_of_options = 0;
        int Lenght_of_options = ((packet[offset+12]>>4)*4)-20;

        while(packet[options_pointer] != 0){

            kind_list = kind_list+to_string(packet[options_pointer])+":";

            if(packet[options_pointer] == 1){

                Number_of_options++;
                options_pointer = options_pointer+1;
                if((options_pointer >= (packet[offset+12]>>4)*4)+offset){

                    break;
                }
                continue;
            }

            int lenght = packet[options_pointer+1];

            if(lenght<=2){

                break;
            }

            options_pointer = options_pointer + lenght;
            Number_of_options++;

            if((options_pointer >= (packet[offset+12]>>4)*4)+offset){

                break;
            }
        }

        l.add_to_file(string(",")+kind_list+string(",")+to_string(Lenght_of_options)+string(",")+to_string(Number_of_options).c_str());
    }

    else {

        l.add_to_file(",,,");
    }

    //----------------------------------------------------------------------------------------------------------------------------



    l.add_to_file("\n");
    l.add_to_file("end");
}
