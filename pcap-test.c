#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "pcap-test.h"
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
		struct libnet_ethernet_hdr *ether = (struct libnet_ethernet_hdr *) packet;
		
		struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *) (packet + sizeof(struct libnet_ethernet_hdr));	
		int ip_length = ipv4->ip_hl * 4;		

		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *) (packet + sizeof(struct libnet_ethernet_hdr) + ip_length);
		int tcp_length = tcp->th_off * 4;


		if(ipv4->ip_p !=6)
			continue;
		//ethernet
		printf("Ethernet Header\n");
		printf("Src mac: ");
		for(int i =0; i< 6;i++){
			printf("%02x", ether->ether_shost[i]);
			if (i !=5)
				printf(":");
			else
				printf("\n");
		}
		printf("Dst mac: ");
		for(int i =0; i< 6;i++){
			printf("%02x", ether->ether_dhost[i]);
			if (i !=5)
				printf(":");
			
			else
				printf("\n");
		}

		//ip
		printf("IP Header\n");
		printf("Src_IP: %s\n", inet_ntoa(ipv4->ip_src));
		printf("Dst_IP: %s\n", inet_ntoa(ipv4->ip_dst));
		
		//tcp
		printf("TCP Header\n");
		printf("Src_Port: %d\n", ntohs(tcp->th_sport));
		printf("Dst_Port: %d\n", ntohs(tcp->th_dport));
		printf("%u bytes captured\n", header->caplen);
		//data
		printf("Data\n");
		for(int i =0; i<20;i++){
			unsigned int header_length = sizeof(struct libnet_ethernet_hdr) + tcp_length + ip_length;
			if( header_length + i < header->caplen ){
				printf("%02X ", packet[header_length + i]);
			}
		}

		printf("\n");
		printf("\n");	
	}

	pcap_close(pcap);
}
