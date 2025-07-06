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

    time_t FlowStart, FlowEnd;
    int TotalBytes, TotalPackets;
    uint8_t ttl_min, ttl_max;
    bool ACK, SYN, RST, FIN;
    string direction;
    string apProtocol;
};

struct FlowMeta
{

    uint64_t TotalBytes = 0, TotalPackets = 0;
    time_t LastSeen;
    deque<time_t> PacketsRecently;
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
    time_t expiry_time;
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
                       time_t FlowStart, time_t FlowEnd,
                       int TotalBytes, int TotalPackets,
                       uint8_t ttl_min, uint8_t ttl_max,
                       bool ACK, bool SYN, bool RST, bool FYN,
                       string direction);

    void expireFlow(time_t now);
    void printFlows() const;
    void updateMeta(string SrcIP, time_t t, uint32_t size);

    void log_to_csv(string SrcIP, string DstIP, uint16_t SrcPort, uint16_t DstPort, uint8_t protocol,string str);

private:
    unordered_map<FlowIdentifier, FlowData, FlowStructHasher> flowTable;
    unordered_map<string, FlowMeta> metaData;
    multimap<time_t, FlowIdentifier> timeIndex;

    vector<FlowTerminated> Terminated_Flow_list;

    const int TIME_OUT = 240;

};
