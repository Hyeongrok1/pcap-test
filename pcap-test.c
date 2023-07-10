#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800

struct libnet_ethernet_hdr {
	u_int8_t ether_dhost[ETHER_ADDR_LEN];
	u_int8_t ether_shost[ETHER_ADDR_LEN];
	u_int16_t ether_type;
};

struct in_addr {
	int first;
	int second;
	int third;
	int fourth;
};

struct libnet_ipv4_hdr {
	u_int8_t ip_hl;
	u_int8_t ip_v;
	u_int8_t ip_tos;
	u_int16_t ip_len;
	u_int16_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_p;
	u_int16_t ip_sum;
	struct in_addr ip_src, ip_dst;
};

void printMac(u_int8_t *m) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x ", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void printIp(struct in_addr ip_addr) {
	printf("%d.%d.%d.%d ", ip_addr.first, ip_addr.second, ip_addr.third, ip_addr.fourth);
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *) packet; 
		printMac(eth_hdr->ether_shost);
		printMac(eth_hdr->ether_dhost);
		printf("\n");
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			continue;
		}
		
		struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *) packet >> sizeof(libnet_ethernet_hdr); 
			


		printf("IP\n");
	}

	pcap_close(pcap);
}
