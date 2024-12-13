#include <fstream>
#include <string.h>
#include <arpa/inet.h>

#include "include/lib.h"
#include "include/router.hpp"

Router::Router(const char *routing_info_filename) {
    ifstream is(routing_info_filename);

	char *p, line[64];

	while (!is.eof()) {
        is.getline(line, 64);

        if (*line == '\n' || *line == '\0') {
            break;
        }

        // read this entry and put it in the routing tree
        // convert all addresses to host endianness, because
        // the radix tree's algorithm supposes that the mask has
        // 1's at the beginning of the number
        route_table_entry *entry = new route_table_entry();

        // read prefix
		p = strtok(line, " ");
        inet_pton(AF_INET, p, (char *)&entry->prefix);
        entry->prefix = ntohl(entry->prefix);

        // read mask
        p = strtok(NULL, " ");
        inet_pton(AF_INET, p, (char *)&entry->next_hop);
        entry->next_hop = ntohl(entry->next_hop);

        // read next hop
        p = strtok(NULL, " ");
        inet_pton(AF_INET, p, (char *)&entry->mask);
        entry->mask = ntohl(entry->mask);

        // read interface
        p = strtok(NULL, " ");
        entry->interface = atoi(p);

        // make this to prevent cases when the prefix is longer than the mask
        entry->prefix = entry->prefix & entry->mask;

        routing_data.add_entry(entry);
	}
}

Router::~Router() {
    for (auto &waiting_package : waiting_packages) {
        delete waiting_package.data;
    }
}

void Router::run() {
    char buf[MAX_PACKET_LEN];

    while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		ether_header *eth_hdr = (ether_header *) buf;

        switch (ntohs(eth_hdr->ether_type)) {
            case ETHERTYPE_IP:
                manage_IPv4_package(interface, buf, len);
                break;
            case ETHERTYPE_ARP:
                manage_ARP_package(interface, buf, len);
                break;
        }
    }
}

void Router::send_over_Ethernet(ether_header *eth_hdr,
                                size_t len,
                                int interface,
                                const mac_address &m) {

    memcpy(eth_hdr->ether_dhost, m.addr, sizeof(m.addr));
    get_interface_mac(interface, eth_hdr->ether_shost);
    send_to_link(interface, (char *)eth_hdr, len);
}

void Router::manage_IPv4_package(int interface, char *buf, size_t len) {
    ether_header *eth_hdr = (ether_header *) buf;
    iphdr *ip_hdr = (iphdr *)(eth_hdr + 1);

    // Check the IPv4 header integrity
    uint16_t check_sum = ntohs(ip_hdr->check);
    ip_hdr->check = 0;

    if (check_sum != checksum((uint16_t *)ip_hdr, sizeof(iphdr))) {
        // Ignore package with invalid checksum
        return;
    }

    // Check TTL
    if (ip_hdr->ttl <= 1) {
        send_ICMP_reply(interface, buf, len, TIME_EXCEEDED);
        return;
    }

    ip_hdr->ttl--;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(iphdr)));

    // check if this package has the router as destination
    char *ip_str = get_interface_ip(interface);
    uint32_t ip;
    inet_pton(AF_INET, ip_str, &ip);
    if (ip == ip_hdr->daddr) {
        if (ip_hdr->protocol == IPPROTO_ICMP) {
            manage_ICMP_package(interface, buf);
        } else {
            // Ignore non-ICMP packages whose destination is this router
            return;
        }
    }

    // Get next hop
    route_table_entry *best_route = routing_data
                                        .find_best(ntohl(ip_hdr->daddr));
    if (best_route == nullptr) {
        send_ICMP_reply(interface, buf, len, DESTINATION_UNREACHABLE);
        return;
    }

    mac_address *dest_mac = get_mac_address(best_route->next_hop);
    if (dest_mac == nullptr) {
        // make an ARP request to find the MAC address of the next hop
        // put this package on a waiting list until then
        char *data = new char[len];
        memcpy(data, buf, len);
        waiting_packages.push_back(waiting_package(best_route->interface, 
                                                    best_route->next_hop, 
                                                    data,
                                                    len));
        generate_ARP_request(best_route->interface, best_route->next_hop);
        return;
    }

    send_over_Ethernet(eth_hdr, len, best_route->interface, *dest_mac);
}

void Router::manage_ICMP_package(int interface, char *buf) {
    iphdr *ip_hdr = (iphdr *)(buf + sizeof(ether_header));
    icmphdr *icmp_hdr = (icmphdr *)(ip_hdr + 1);

    // send echo reply
    icmp_hdr->type = 0;
    icmp_hdr->code = 0;

    // remake ICMP header checksum
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
                                    ntohs(ip_hdr->tot_len) - sizeof(iphdr)));

    // swap IP fields in IPv4 header
    uint32_t aux = ip_hdr->daddr;
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = aux;

    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(iphdr)));
}

void Router::update_MAC_info(uint32_t ip, const mac_address& m) {
    mac_info.insert({ip, m});

    // see if any waiting package can be now sent to this destination
    auto iter_waiting = waiting_packages.begin();

    while (iter_waiting != waiting_packages.end()) {
        if (iter_waiting->ip == ip) {
            // send this package
            send_over_Ethernet((ether_header *)iter_waiting->data,
                                iter_waiting->len,
                                iter_waiting->interface,
                                m);
            delete iter_waiting->data;
            iter_waiting = waiting_packages.erase(iter_waiting);
        } else {
            iter_waiting++;
        }
    }
}

void Router::generate_ARP_request(int interface, uint32_t ip) {
    constexpr uint8_t broadcast_address[] = {0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF};

    char package[sizeof(ether_header) + sizeof(arp_header)];

    ether_header *eth_hdr = (ether_header *) package;
    arp_header *arp_hdr = (arp_header *)(eth_hdr + 1);

    // complete ARP Header
    arp_hdr->htype = htons(1);                  // for Ethernet
    arp_hdr->ptype = htons(ETHERTYPE_IP);       // for IPv4
    arp_hdr->hlen = sizeof(mac_address::addr);  // size of MAC address
    arp_hdr->plen = sizeof(iphdr::daddr);       // size of IPv4 address
    arp_hdr->op = htons(1);                     // REQUEST

    // complete with this interface's data (IP and MAC addresses)
    get_interface_mac(interface, arp_hdr->sha);
    char *spa_char = get_interface_ip(interface);
    inet_pton(AF_INET, spa_char, &arp_hdr->spa);

    // complete with the requested host's data (MAC address is
    // filled with 0 since we don't know it)
    memset(arp_hdr->tha, 0, sizeof(mac_address::addr));
    arp_hdr->tpa = htonl(ip);

    // complete Ethernet Header
    get_interface_mac(interface, eth_hdr->ether_shost);
    memcpy(eth_hdr->ether_dhost, broadcast_address, sizeof(broadcast_address));
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    send_to_link(interface, package, sizeof(package));
}

void Router::generate_ARP_reply(arp_request& request, const mac_address& m) {
    ether_header *eth_hdr = (ether_header *)request.data;
    arp_header *arp_hdr = (arp_header *)(eth_hdr + 1);

    // recreate ARP header
    arp_hdr->op = htons(2);     // REPLY

    // interchange source and destination
    uint32_t aux = arp_hdr->spa;
    arp_hdr->spa = arp_hdr->tpa;
    arp_hdr->tpa = aux;

    memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->sha));

    // complete information regarding the mac address
    memcpy(arp_hdr->sha, m.addr, sizeof(m.addr));

    mac_address dest;
    memcpy(dest.addr, arp_hdr->tha, sizeof(arp_hdr->tha));

    send_over_Ethernet(eth_hdr, request.len, request.interface, dest);
}

void Router::manage_ARP_package(int interface, char *buf, size_t len) {
    ether_header *eth_hdr = (ether_header *) buf;
    arp_header *arp_hdr = (arp_header *)(eth_hdr + 1);

    // update router's cache with the MAC address of this host
    if (mac_info.find(ntohl(arp_hdr->spa)) == mac_info.end()) {
        mac_address m;
        memcpy(m.addr, arp_hdr->sha, sizeof(m.addr));

        update_MAC_info(ntohl(arp_hdr->spa), m);
    }

    // if this is not a request, drop it
    if (ntohs(arp_hdr->op) != 1) {
        return;
    }

    // test if this is exactly router's ip
    char *ip_str = get_interface_ip(interface);
    uint32_t ip;
    inet_pton(AF_INET, ip_str, &ip);

    if (ip == arp_hdr->tpa) {
        // reply to this request by sending this interface's MAC address
        arp_request arp(interface, ntohl(arp_hdr->tpa), buf, len);
        mac_address m;
        get_interface_mac(interface, m.addr);
        generate_ARP_reply(arp, m);
    }
}

void Router::send_ICMP_reply(int interface,
                            char *buf,
                            size_t len,
                            icmp_constants response_type) {
    
    // response contains an Ethernet header, an IP header, an ICMP header
    // which contains an IP header and (at most) another 8 bytes
    char response[sizeof(ether_header) +
                    2 * sizeof(iphdr) +
                    sizeof(icmphdr) +
                    8];
    size_t response_len;

    ether_header *eth_hdr = (ether_header *)response;
    iphdr *ip_hdr = (iphdr *)(eth_hdr + 1);
    icmphdr *icmp_hdr = (icmphdr *)(ip_hdr + 1);
    iphdr *ip_hdr_over_icmp = (iphdr *)(icmp_hdr + 1);

    switch (response_type) {
        case DESTINATION_UNREACHABLE:
            icmp_hdr->type = 3;
            icmp_hdr->code = 0;
            break;
        case TIME_EXCEEDED:
            icmp_hdr->type = 11;
            icmp_hdr->code = 0;
            break;
        default:
            return;
    }

    // copy the IP header from buf and the first 8 bytes from payload
    // (or the size of payload if it is smaller than that)
    if (len - sizeof(ether_header) - sizeof(iphdr) > 8) {
        response_len = sizeof(response);
        memcpy(ip_hdr_over_icmp,
                buf + sizeof(ether_header),
                8 + sizeof(iphdr));
    } else {
        response_len = len + sizeof(iphdr) + sizeof(icmphdr);
        memcpy(ip_hdr_over_icmp,
                buf + sizeof(ether_header),
                len - sizeof(ether_header));
    }

    // remake IPv4 header
    memcpy(ip_hdr, buf + sizeof(ether_header), sizeof(iphdr));
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->ttl = 64;

    ip_hdr->tot_len = htons(response_len - sizeof(ether_header));

    ip_hdr->daddr = ip_hdr->saddr;
    char *ip_router = get_interface_ip(interface);
    inet_pton(AF_INET, ip_router, &ip_hdr->saddr);

    ip_hdr->check = 0;
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(iphdr));

    // send package
    mac_address m;
    memcpy(m.addr, ((ether_header *)buf)->ether_shost, sizeof(m.addr));
    eth_hdr->ether_type = htons(ETHERTYPE_IP);

    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
                                        response_len
                                            - sizeof(ether_header)
                                            - sizeof(iphdr)));

    send_over_Ethernet(eth_hdr, response_len, interface, m);
}
