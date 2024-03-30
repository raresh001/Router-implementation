#include <map>
#include <list>
#include <iostream>
#include <fstream>
#include <exception>
#include <string.h>
#include <arpa/inet.h>

#include "include/lib.h"
#include "include/protocols.h"

using namespace std;

enum ethertype_constants {
    ETHERTYPE_IP = 0x0800,
    ETHERTYPE_ARP = 0x0806
};

enum icmp_constants {
    DESTINATION_UNREACHABLE,
    TIME_EXCEEDED
};

class radix_tree {
public:
    radix_tree() { root = nullptr; }
    ~radix_tree() { if (root) delete_rec(root); }

    void add_entry(route_table_entry *entry) { root = add_route_rec(root, entry); }
    route_table_entry *find_best(uint32_t ip);
private:
    struct node;
    node *root;

    // get a mask reprezenting the common part of the 2 IP addresses
    // which is blocked to mask's size
    uint32_t compute_common(uint32_t ip1, uint32_t ip2, uint32_t mask);
    void delete_rec(node *tree);
    node *add_route_rec(node *tree, route_table_entry *entry);
};

struct radix_tree::node {
    route_table_entry *entry;
    uint32_t label;
    uint32_t label_mask;
    node *left;
    node *right;

    node(route_table_entry *_entry) {
        entry = _entry;
        label = entry->prefix;
        label_mask = entry->mask;
        left = right = nullptr;
    }

    node(uint32_t _label, uint32_t _label_mask) {
        entry = nullptr;
        label = _label;
        label_mask = _label_mask;
        left = right = nullptr;
    }
};

struct mac_address {
    uint8_t addr[6];
};

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

struct arp_request {
    int interface;
    uint32_t ip_requested;
    char *data;
    size_t len;

    arp_request(int _interface, uint32_t _ip_requested, char *_data, size_t _len) {
        interface = _interface;
        ip_requested = _ip_requested;
        data = _data;
        len = _len;
    }
};

class Router {
public:
    Router(const char *routing_info_file);
    void run();

private:
    radix_tree routing_data;
    map<uint32_t, mac_address> mac_info;
    list<waiting_package> waiting_packages;
    list<arp_request> arp_requests;

    // find mac address of the host with the given ip
    // use arp request
    mac_address *get_mac_address(uint32_t ip) {
        auto iter = mac_info.find(ip);
        if (iter != mac_info.end()) {
            return &iter->second;
        }
        return nullptr;
    }

    // send the package that starts with eth_hdr to address 
    // specified by m using the given interface
    void send_over_Ethernet(ether_header *eth_hdr, size_t len, int interface, const mac_address &m);

    void manage_IPv4_package(int interface, char *buf, size_t len);

    // add m to the MAC information cache of the router 
    // and update the pending requests to its IP address
    void update_MAC_info(uint32_t ip, const mac_address& m);

    void generate_ARP_request(int interface, uint32_t ip);
    void generate_ARP_reply(arp_request& request, const mac_address& m);
    void manage_ARP_package(int interface, char *buf, size_t len);

    void manage_ICMP_package(int interface, char *buf, size_t len);
    void send_ICMP_reply(int interface, char *buf, size_t len, icmp_constants response_type);
};

void radix_tree::delete_rec(radix_tree::node *tree) {
    if (tree->left) {
        delete_rec(tree->left);
    }
    if (tree->right) {
        delete_rec(tree->right);
    }

    delete tree->entry;
    delete tree;
}

uint32_t radix_tree::compute_common(uint32_t ip1, uint32_t ip2, uint32_t mask) {
    uint32_t common = (~(ip1 ^ ip2)) & mask;
    uint32_t aux = 0x80000000;
    while (common & aux) {
        aux >>= 1;
    }
    return common & (~((aux << 1) - 1));
}

radix_tree::node *radix_tree::add_route_rec(radix_tree::node *tree, route_table_entry *entry) {
    if (tree == nullptr) {
        return new node(entry);
    }

    uint32_t common_mask = compute_common(tree->label, 
                                        entry->prefix, 
                                        tree->label_mask & entry->mask);

    if (common_mask < tree->label_mask) {
        // create an intermediary node, whose label is 
        // the common part of tree->label and entry->prefix
        node *intermediary = new node(tree->label & common_mask, common_mask);

        // test which side tree should be attached to
        if (tree->label & (common_mask >> 1) & (~common_mask)) {
            intermediary->right = tree;
        } else {
            intermediary->left = tree;
        }

        if (common_mask == entry->mask) {
            intermediary->entry = entry;
        } else if (intermediary->left) {
            intermediary->right = new node(entry);
        } else {
            intermediary->left = new node(entry);
        }

        return intermediary;
    }

    if (entry->mask == tree->label_mask) {
        // entry should be put exactly here
        if (tree->entry == nullptr)  {
            tree->entry = entry;
        }

        return tree;
    }

    // insert entry in the correct child
    if (entry->prefix & (common_mask >> 1) & (~common_mask)) {
        tree->right = add_route_rec(tree->right, entry);
    } else {
        tree->left = add_route_rec(tree->left, entry);
    }

    return tree;
}

route_table_entry *radix_tree::find_best(uint32_t ip) {
    node *iter = root;
    route_table_entry *best = nullptr;

    while (iter) {
        if (iter->label != (ip & iter->label_mask)) {
            // none of the nodes from this subtree can fit ip
            break;
        }

        if (iter->entry) {
            // this is the node with the biggest mask that fits ip
            best = iter->entry;
        }

        if (ip & (iter->label_mask >> 1) & (~iter->label_mask)) {
            iter = iter->right;
        } else {
            iter = iter->left;
        }
    }

    return best;
}

Router::Router(const char *routing_info_filename) {
    ifstream is(routing_info_filename);

	char *p, line[64];

	while (!is.eof()) {
        is.getline(line, 64);

        if (*line == '\n' || *line == '\0') {
            break;
        }

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

        entry->prefix = entry->prefix & entry->mask;

        routing_data.add_entry(entry);
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
            manage_ICMP_package(interface, buf, len);
        } else {
            cout << "Ignore non-ICMP packages" << endl;
            return;
        }
    }

    // Get next hop
    route_table_entry *best_route = routing_data.find_best(ntohl(ip_hdr->daddr));
    if (best_route == nullptr) {
        send_ICMP_reply(interface, buf, len, DESTINATION_UNREACHABLE);
        return;
    }

    mac_address *dest_mac = get_mac_address(best_route->next_hop);
    if (dest_mac == nullptr) {
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

void Router::manage_ICMP_package(int interface, char *buf, size_t len) {
    iphdr *ip_hdr = (iphdr *)(buf + sizeof(ether_header));
    icmphdr *icmp_hdr = (icmphdr *)(ip_hdr + 1);

    // send echo reply
    icmp_hdr->type = 0;
    icmp_hdr->code = 0;

    // remake ICMP header checksum
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(icmphdr)));

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

    // see if any arp request can now be replied with this information
    auto iter_arp = arp_requests.begin();

    while (iter_arp != arp_requests.end()) {
        if (iter_arp->ip_requested == ip) {
            generate_ARP_reply(*iter_arp, m);
            delete iter_arp->data;
            iter_arp = arp_requests.erase(iter_arp);
        } else {
            iter_arp++;
        }
    }
}

void Router::generate_ARP_request(int interface, uint32_t ip) {
    constexpr uint8_t broadcast_address[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    char package[sizeof(ether_header) + sizeof(arp_header)];

    ether_header *eth_hdr = (ether_header *) package;
    arp_header *arp_hdr = (arp_header *)(eth_hdr + 1);

    // complete ARP Header
    arp_hdr->htype = htons(1);                  // for Ethernet
    arp_hdr->ptype = htons(ETHERTYPE_IP);       // for IPv4
    arp_hdr->hlen = sizeof(mac_address::addr);  // size of MAC address
    arp_hdr->plen = sizeof(iphdr::daddr);       // size of IPv4 address
    arp_hdr->op = htons(1);                     // REQUEST

    get_interface_mac(interface, arp_hdr->sha);
    char *spa_char = get_interface_ip(interface);
    inet_pton(AF_INET, spa_char, &arp_hdr->spa);

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
        return;
    }

    // see if the router knows the MAC address of the requested host
    auto mac_iter = mac_info.find(ntohl(arp_hdr->tpa));

    if (mac_iter != mac_info.end()) {
        arp_request arp(interface, ntohl(arp_hdr->tpa), buf, len);
        generate_ARP_reply(arp, mac_iter->second);
    } else {
        char *data = new char[len];
        memcpy(data, buf, len);
        arp_requests.push_back(arp_request(interface, ntohl(arp_hdr->tpa), buf, len));
    }
}

void Router::send_ICMP_reply(int interface, char *buf, size_t len, icmp_constants response_type) {
    char response[sizeof(ether_header) + 2 * sizeof(iphdr) + sizeof(icmphdr) + 8];
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

    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(icmphdr)));

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

    cout << "Termini fct cu " << response_type << endl;
    send_over_Ethernet(eth_hdr, response_len, interface, m);
}

int main(int argc, char *argv[]) {
	init(argc - 2, argv + 2);
    Router *router;

    try {
        router = new Router(argv[1]);
        router->run();
        delete router;
    } catch (exception &e) {
        cout << "Error occured: " << e.what() << endl;
    }

	return 0;
}