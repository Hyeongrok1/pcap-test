#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#define ETHER_ADDR_LEN 6
#define ETHER_SIZE 14
#define ETHERTYPE_IP 0x0800
#define IPTYPE_TCP 0x06

struct libnet_ethernet_hdr {
	u_int8_t ether_dhost[ETHER_ADDR_LEN];
	u_int8_t ether_shost[ETHER_ADDR_LEN];
	u_int16_t ether_type;
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl;      	  /* header length */
    u_int8_t ip_tos;          /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;         /* sequence number */
    u_int32_t th_ack;         /* acknowledgement number */
	u_int8_t  th_off;         /* (unused) */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void printMac(u_int8_t *m) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void printIp(struct in_addr ip_addr) {
	int first = (ip_addr.s_addr & 0xff);
	int second = (ip_addr.s_addr >> 8) & 0xff;
	int third = (ip_addr.s_addr >> 16) & 0xff;
	int fourth = (ip_addr.s_addr >> 24) & 0xff;

	printf("%d.%d.%d.%d\n", first, second, third, fourth);
}

void printPort(u_int16_t port) {
	printf("%d\n", ntohs(port));
}

void printData(u_int8_t *data, int payload_size) {
	if (payload_size == 0) printf("0 bytes");
	for (int i = 0; i < 10; i++) {
		if (i == payload_size) break;
		printf("%02x ", data[i]);
	}
	printf("\n");
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
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *) packet; 
		
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			continue;
		}
		
		struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *) (packet + ETHER_SIZE);
		
		if (ipv4_hdr->ip_p != IPTYPE_TCP) {
			continue;
		}

		size_t ip_size = 4*(ipv4_hdr->ip_hl & 0x0f);
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *) (packet + ETHER_SIZE + ip_size);
		size_t tcp_size = sizeof(*tcp_hdr);
		
		u_int8_t* data = (u_int8_t*) (packet + ETHER_SIZE + ip_size + tcp_size);
		int payload_size = ntohs(ipv4_hdr->ip_len) - ip_size - tcp_size;
		printf("%d ", payload_size);
		printf("\n%u bytes captured\n", header->caplen);
		printf("Ethernet Header Source Mac: ");
		printMac(eth_hdr->ether_shost);
		printf("  Ethernet Header Dest Mac: ");
		printMac(eth_hdr->ether_dhost);
		printf("     IPv4 Header Source IP: ");
		printIp(ipv4_hdr->ip_src);
		printf("       IPv4 Header Dest IP: ");
		printIp(ipv4_hdr->ip_dst);
		printf("    TCP Header Source Port: ");
		printPort(tcp_hdr->th_sport);
		printf("      TCP Header Dest Port: ");
		printPort(tcp_hdr->th_dport);
		printf("             Payload(Data): ");
		printData(data, payload_size);
		printf("\n");
	}

	pcap_close(pcap);
}
