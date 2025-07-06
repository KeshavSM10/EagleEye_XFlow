#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <iomanip>

#include "FlowTracker.h"
#include <string>
#include <functional>

#include <map>
#include <unordered_map>
#include <unordered_set>

#include <iostream>
#include <vector>

#include"Logger.h"

using namespace std;

//-------------------------------------------------------------------------------------------------------------------------------

bool FlowIdentifier::operator==(const FlowIdentifier &other) const
{

    if (other.SrcIP == SrcIP && other.DstIP == DstIP && other.SrcPort == SrcPort && other.DstPort == DstPort && other.Protocol == Protocol)
    {

        return true;
    }

    return false;
}

//---------------------------------------------------------------------------------------------------------------------------


vector<string> FlowTracker::getMyIP()
{
    vector<string> ipList;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return ipList;

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &bufferSize); // AF_UNSPEC => both IPv4 and IPv6

    IP_ADAPTER_ADDRESSES* adapterAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapterAddresses, &bufferSize) != NO_ERROR)
    {
        free(adapterAddresses);
        WSACleanup();
        return ipList;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = adapterAddresses; adapter != nullptr; adapter = adapter->Next)
    {
        for (IP_ADAPTER_UNICAST_ADDRESS* addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next)
        {
            SOCKADDR* sa = addr->Address.lpSockaddr;
            char buffer[INET6_ADDRSTRLEN] = {0};

            if (sa->sa_family == AF_INET) {
                getnameinfo(sa, sizeof(sockaddr_in), buffer, sizeof(buffer), nullptr, 0, NI_NUMERICHOST);
                ipList.emplace_back(buffer);
            }
            else if (sa->sa_family == AF_INET6) {
                getnameinfo(sa, sizeof(sockaddr_in6), buffer, sizeof(buffer), nullptr, 0, NI_NUMERICHOST);
                std::string ip6 = buffer;

                if (!ip6.starts_with("fe80") && ip6 != "::1") {
                    ipList.emplace_back(ip6);
                }
            }
        }
    }

    free(adapterAddresses);
    WSACleanup();
    return ipList;
}


//------------------------------------------------------------------------------------------------------------------------------

size_t FlowStructHasher::operator()(const FlowIdentifier &other) const
{

    size_t h1 = hash<string>()(other.SrcIP);
    size_t h2 = hash<string>()(other.DstIP);
    size_t h3 = hash<uint16_t>()(other.SrcPort);
    size_t h4 = hash<uint16_t>()(other.DstPort);
    size_t h5 = hash<uint8_t>()(other.Protocol);

    size_t Hash_tag = h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    return Hash_tag;
}

//-------------------------------------------------------------------------------------------------------------------------------

void FlowTracker::processPacket(string SrcIP, string DstIP, uint16_t SrcPort, uint16_t DstPort, uint8_t protocol, time_t flowStart, time_t flowEnd, int packetSize, int TotalPackets, uint8_t ttl_min, uint8_t ttl_max, bool ack, bool syn, bool rst, bool fin, string direction) {

    FlowIdentifier f;
    f.SrcIP = SrcIP;
    f.DstIP = DstIP;
    f.SrcPort = SrcPort;
    f.DstPort = DstPort;
    f.Protocol = protocol;


    auto Flow_iden = flowTable.find(f);
    if (Flow_iden == flowTable.end()) {


        FlowData newFlowIdentifierData;
        newFlowIdentifierData.FlowStart = flowStart;
        newFlowIdentifierData.FlowEnd = flowEnd;
        newFlowIdentifierData.TotalBytes = packetSize;
        newFlowIdentifierData.TotalPackets = 1;
        newFlowIdentifierData.ttl_max = ttl_max;
        newFlowIdentifierData.ttl_min = ttl_min;
        newFlowIdentifierData.SYN = syn;
        newFlowIdentifierData.RST = rst;
        newFlowIdentifierData.FIN = fin;
        newFlowIdentifierData.ACK = ack;

        if (set_IP.find(SrcIP) != set_IP.end()) {

            newFlowIdentifierData.direction = "OUT";
        }

        else if (set_IP.find(DstIP) != set_IP.end()) {

            newFlowIdentifierData.direction = "IN";
        }
        else {

            newFlowIdentifierData.direction = "MULTICAST";
        }

        flowTable.emplace(f, newFlowIdentifierData);
        timeIndex.insert({flowEnd, f});
    }

    else {

        auto &FlowDataPointer = Flow_iden->second;

        time_t oldFlowEnd = FlowDataPointer.FlowEnd;

        FlowDataPointer.TotalPackets++;
        FlowDataPointer.TotalBytes += packetSize;
        FlowDataPointer.FlowEnd = flowEnd;
        FlowDataPointer.ttl_max = max(ttl_max, FlowDataPointer.ttl_max);
        FlowDataPointer.ttl_min = min(ttl_min, FlowDataPointer.ttl_min);
        FlowDataPointer.ACK |= ack;
        FlowDataPointer.FIN |= fin;
        FlowDataPointer.RST |= rst;
        FlowDataPointer.SYN |= syn;

        if (set_IP.find(SrcIP) != set_IP.end()) {

            FlowDataPointer.direction = "OUT";
        }

        else if (set_IP.find(DstIP) != set_IP.end()) {

            FlowDataPointer.direction = "IN";
        }
        else {

            FlowDataPointer.direction = "MULTICAST";
        }

        for (auto it = timeIndex.lower_bound(oldFlowEnd); it != timeIndex.upper_bound(oldFlowEnd);) {

            if (it->second == f) {
                it = timeIndex.erase(it);
                break;
            }
            else {
                ++it;
            }
        }

        timeIndex.insert({flowEnd, f});
    }

    cout << endl
         << "----------------------------------------------------------------------------------------------" << endl;
    cout << " ::ok   ::";
    cout << " :" << flowTable[f].FlowStart << " :" << flowTable[f].FlowEnd << " :" << flowTable[f].direction
         << " :" << flowTable[f].TotalBytes << " :" << flowTable[f].TotalPackets << endl;
}

//-------------------------------------------------------------------------------------------------------------------------------

void FlowTracker::updateMeta(string srcIP, time_t curr_t, uint32_t size) {

    auto meta_iden = metaData.find(srcIP);
    if (meta_iden == metaData.end()) {

        FlowMeta meta;
        meta.LastSeen = curr_t;
        meta.TotalBytes += size;
        meta.TotalPackets++;
        meta.PacketsRecently.push_back(curr_t);
        metaData[srcIP] = meta;
    }

    else {

        auto &meta_d = meta_iden->second;
        meta_d.LastSeen = curr_t;
        meta_d.TotalBytes += size;
        meta_d.TotalPackets++;
        meta_d.PacketsRecently.push_back(curr_t);

        time_t window = 10;
        while (!meta_d.PacketsRecently.empty() && curr_t - meta_d.PacketsRecently.front() > 10) {

            meta_d.PacketsRecently.pop_front();
        }
    }

    cout<<endl<<"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;
    cout<< " :" << metaData[srcIP].LastSeen<< " :" << metaData[srcIP].TotalBytes<< " :" << metaData[srcIP].TotalPackets<<endl;
}

//-------------------------------------------------------------------------------------------------------------------------------

void FlowTracker::expireFlow(time_t now) {

    auto it = timeIndex.begin();
    while (!timeIndex.empty() && now - TIME_OUT > it->first) {

        FlowIdentifier fID = it->second;

        FlowTerminated flowterminated;
        flowterminated.expiry_time = it->first;
        flowterminated.fI = fID;
        flowterminated.fD = flowTable[fID];
        flowterminated.fM = metaData[fID.SrcIP];

        cout<<endl<<"................................................................................................."<<endl;
        cout<<" : "<<flowterminated.expiry_time<<" : "<<flowterminated.fD.TotalBytes<<" : "<<flowterminated.fD.TotalPackets<<" : "<<flowterminated.fI.SrcIP<<endl;

        Terminated_Flow_list.push_back(flowterminated);

        flowTable.erase(fID);
        metaData.erase(fID.SrcIP);
        it = timeIndex.erase(it);
    }
}

void FlowTracker::log_to_csv(string SrcIP, string DstIP, uint16_t SrcPort, uint16_t DstPort, uint8_t protocol,string str) {

    File_logging l_FA;
    
    FlowIdentifier _f;
    _f.DstIP = DstIP;
    _f.DstPort = DstPort;
    _f.Protocol = protocol;
    _f.SrcIP = SrcIP;
    _f.SrcPort = SrcPort;

    FlowStructHasher hasher;
    size_t hash = hasher(_f);

    string Log_in = "";
    Log_in = Log_in + _f.SrcIP + ",";
    Log_in = Log_in + _f.DstIP + ",";
    Log_in = Log_in + to_string(_f.SrcPort) + ",";
    Log_in = Log_in + to_string(_f.DstPort) + ",";
    Log_in = Log_in + to_string(_f.Protocol) + ",";

    Log_in += to_string(hash);
    Log_in += ",";

    l_FA.add_init(Log_in);

    uint32_t total_bytes_in_conversation;
    total_bytes_in_conversation += metaData[SrcIP].TotalBytes;
    if(metaData.find(DstIP) != metaData.end()) {

        total_bytes_in_conversation += metaData[SrcIP].TotalBytes;
    }

    l_FA.add_init(string(to_string(flowTable[_f].FlowStart) + ",").c_str());
    l_FA.add_init(string(to_string(flowTable[_f].FlowEnd) + ",").c_str());
    l_FA.add_init(string(to_string(flowTable[_f].TotalBytes) + ",").c_str());
    l_FA.add_init(string(to_string(flowTable[_f].ttl_min) + ",").c_str());
    l_FA.add_init(string(to_string(flowTable[_f].ttl_max) + ",").c_str());
    l_FA.add_init(string(to_string(flowTable[_f].TotalPackets) + ",").c_str());
    l_FA.add_init(string(flowTable[_f].direction + ",").c_str());
    l_FA.add_init(string(to_string(flowTable[_f].SYN) + ",").c_str());
    l_FA.add_init(string(to_string(flowTable[_f].RST) + ",").c_str());
    l_FA.add_init(string(to_string(flowTable[_f].ACK) + ",").c_str());
    l_FA.add_init(string(to_string(flowTable[_f].FIN) + ",").c_str());
    l_FA.add_init(string(to_string(total_bytes_in_conversation) + ",").c_str());

    l_FA.add_init(str);
    l_FA.add_init("\n");
    l_FA.add_init("end");
}



//Source IP,Destination IP,Src Port,Dst Port,Protocol_L4,Flow Hash,Flow start,Flow End,Total Bytes from Src IP,
//TTL MIN, TTL MAX,Total Packets from Src IP,Direction,SYN Flag,RST Flag,ACK Flag,FIN Flag,Total Bidirectional Bytes,APPLICATION LAYER PROTOCOL,
//App layer port,Protocol Sprecific Information";
