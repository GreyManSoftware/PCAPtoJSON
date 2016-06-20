#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define SNAPLEN 65536

void print_usage();

void process_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

void process_ip(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer, int offset);

typedef struct Packet
{
	struct timeval datetime;
	char daddr[16];
	char saddr[16];
	uint16_t dport;
	uint16_t sport;
	int8_t proto;
} Packet;

void packet_to_json(Packet p);
