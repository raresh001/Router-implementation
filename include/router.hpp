#ifndef _ROUTER_HPP
#define _ROUTER_HPP

#include <map>
#include <list>

#include "protocols.h"
#include "radix_tree.hpp"

using namespace std;

enum ethertype_constants {
    ETHERTYPE_IP = 0x0800,
    ETHERTYPE_ARP = 0x0806
};

enum icmp_constants {
    DESTINATION_UNREACHABLE,
    TIME_EXCEEDED
};

struct mac_address {
    uint8_t addr[6];
};

// this package is queued if the router doesn't know the MAC address of next hop
struct waiting_package {
    int interface;
    uint32_t ip;
    char *data;
    size_t len;

    waiting_package(int _interface, uint32_t _ip, char *_data, size_t _len) {
        interface = _interface;
        ip = _ip;
        data = _data;
        len = _len;
    }
};

// this package is queued if the router doesn't know the requested MAC address
struct arp_request {
    int interface;
    uint32_t ip_requested;
    char *data;
    size_t len;

    arp_request(int _interface,
                uint32_t _ip_requested,
                char *_data,
                size_t _len) {
        interface = _interface;
        ip_requested = _ip_requested;
        data = _data;
        len = _len;
    }
};

class Router {
public:
    Router(const char *routing_info_file);
    ~Router();
    void run();

private:
    radix_tree routing_data;
    map<uint32_t, mac_address> mac_info;
    list<waiting_package> waiting_packages;

    // find mac address of the host with the given ip
    mac_address *get_mac_address(uint32_t ip) {
        auto iter = mac_info.find(ip);
        if (iter != mac_info.end()) {
            return &iter->second;
        }
        return nullptr;
    }

    // send the package that starts with eth_hdr to address 
    // specified by m using the given interface
    void send_over_Ethernet(ether_header *eth_hdr,
                            size_t len,
                            int interface,
                            const mac_address &m);

    void manage_IPv4_package(int interface, char *buf, size_t len);

    // add m to the MAC information cache of the router 
    // and update the pending requests to its IP address
    void update_MAC_info(uint32_t ip, const mac_address& m);

    void generate_ARP_request(int interface, uint32_t ip);
    void generate_ARP_reply(arp_request& request, const mac_address& m);
    void manage_ARP_package(int interface, char *buf, size_t len);

    // update the fields from IPv4 and ICMP headers
    // this function does NOT send the package;
    // this is done in manage_IPv4_package 
    void manage_ICMP_package(int interface, char *buf);

    // send an ICMP reply back to sender (for destination unreachable
    // and time exceeded)
    void send_ICMP_reply(int interface,
                        char *buf,
                        size_t len,
                        icmp_constants response_type);
};

#endif  // _ROUTER_HPP