#pragma once
#include <string>
#include <unordered_map>
#include <deque>
#include <time.h>
#include <cstdint>
#include <functional>
#include <map>
#include <unordered_set>
#include <vector>
#include <chrono>
using namespace std;

struct FlowIdentifier
{

    string SrcIP, DstIP;
    uint16_t SrcPort, DstPort;
    uint8_t Protocol;

    bool operator==(const FlowIdentifier &other) const;
};

struct FlowData
{

    chrono::nanoseconds FlowStart, FlowEnd;
    int TotalBytes, TotalPackets;
    uint8_t ttl_min, ttl_max;
    bool ACK, SYN, RST, FIN;
    string direction;
    string apProtocol;
    double periodic_avg;
};

struct FlowMeta
{

    uint64_t TotalBytes = 0, TotalPackets = 0;
    chrono::nanoseconds LastSeen;
    deque<chrono::nanoseconds> PacketsRecently;
};

struct FlowStructHasher
{

    size_t operator()(const FlowIdentifier &key) const;
};

struct FlowTerminated
{

    FlowIdentifier fI;
    FlowData fD;
    FlowMeta fM;
    chrono::nanoseconds expiry_time;
};

class FlowTracker
{

public:
    vector<string> myIP;
    unordered_set<string> set_IP;
    
    FlowTracker()
    {
        
        this->myIP = getMyIP();
        this->set_IP = unordered_set<string>(myIP.begin(), myIP.end());
    }

    vector<string> getMyIP();
    
    void processPacket(string SrcIP, string DstIP, uint16_t SrcPort,
                       uint16_t DstPort, uint8_t protocol,
                       chrono::nanoseconds FlowStart, chrono::nanoseconds FlowEnd,
                       int TotalBytes, int TotalPackets,
                       uint8_t ttl_min, uint8_t ttl_max,
                       bool ACK, bool SYN, bool RST, bool FYN,
                       string direction);

    void expireFlow(chrono::nanoseconds s);
    void printFlows() const;
    void updateMeta(string SrcIP, chrono::nanoseconds t, uint32_t size);

    void log_to_csv(string SrcIP, string DstIP, uint16_t SrcPort, uint16_t DstPort, uint8_t protocol,string str);

    double calculate_Entropy(const string& s);
    unordered_map<FlowIdentifier, vector<FlowData>, FlowStructHasher> Packet_list;

    //unordered_map <chrono::nanoseconds time, pair<uint64_t, uint64_t>> Agg_Data;

private:
    unordered_map<FlowIdentifier, FlowData, FlowStructHasher> flowTable;
    unordered_map<string, FlowMeta> metaData;
    multimap<chrono::nanoseconds, FlowIdentifier> timeIndex;

    vector<FlowTerminated> Terminated_Flow_list;

    chrono::nanoseconds TIME_OUT = chrono::seconds(100);
};
