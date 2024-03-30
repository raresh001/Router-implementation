#include "queue.h"
#include "lib.h"
#include "protocols.h"

struct route_table_entry *get_next_hop(uint32_t ip) {
	#warning TODO
	return NULL;
}

void compute_icmp_reply() {

}

void compute_ipv4_reply(char *buf, size_t len)
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// check if the package is corrupt
	uint16_t package_checksum = ntoh(ip_hdr->check);

	ip_hdr->check = 0;
	if (package_checksum != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
		// drop the package
		return;
	}

	// treat icmp requests separately
	#warning TODO

	if (ip_hdr->ttl <= 1) {
		// drop the package
		return;
	}

	uint8_t old_ttl = ip_hdr->ttl;
	ip_hdr->ttl--;

	// actualize checksum
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

	struct route_table_entry* best_route = get_next_hop(ip_hdr->daddr);
	
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}


