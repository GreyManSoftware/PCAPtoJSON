#include "pcaptojson.h"

int packet_count = 0;

void print_usage ()
{
	fprintf(stderr, "Usage: [-r <input_file>] [-w output_file]");
}

void process_pkt (u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	if (ntohs(*(uint16_t *)(buffer+14))==0x0800)
	{
		process_ip(args, header, buffer, 16);
	}   
	else if (ntohs(*(uint16_t *)(buffer+12))==0x0800)
	{
		process_ip(args, header, buffer, 14);
	}   
}

void process_ip (u_char *args, const struct pcap_pkthdr *header, const u_char *buffer, int offset)
{
	struct iphdr *ip = (struct iphdr *)(buffer+offset);
	struct tcphdr *tcp;
	struct udphdr *udp;

	char dst_ip[16], src_ip[16];
	uint32_t hash;
	uint16_t sport, dport;
	uint8_t nproto = ip->protocol;
	
	strcpy(dst_ip, inet_ntoa(* (struct in_addr *) &ip->daddr));
	strcpy(src_ip, inet_ntoa(* (struct in_addr *) &ip->saddr));

	printf("%d: Proto: %d - src: %s - dst: %s - ", packet_count++, ip->protocol, dst_ip, src_ip);

	switch (nproto)
	{
		case 6:
			//TCP
			tcp = (struct tcphdr *)(buffer+offset+(ip->ihl*4));
			sport = tcp->source;
			dport = tcp->dest;
			break;
		case 17:
			//UDP
			udp = (struct udphdr *)(buffer+offset+(ip->ihl*4));
			sport = udp->source;
			dport = udp->dest;
			break;
		default:
			fprintf(stderr, "Proto unknown\n");
			sport = 0;
			dport = 0;
			break;
	}
	
	printf("src_port: %d - dst_port: %d\n", ntohs(sport), ntohs(dport));
}

int main (int argc, char **argv)
{
	int opt;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *file_name = "-";
	char *outfile = NULL;
	
	//parse args

	while ((opt = getopt(argc, argv, "r:w:")) != -1)
	{
		switch(opt)
		{
			case 'r':
				file_name = optarg;
				break;

			case 'w':
				outfile = optarg;
				break;

			case '?':
				if (optopt == 'r')
				{
					print_usage(argv[0]);
					printf("-r <file.pcap>\n");
					exit(-1);
				}
				else if (optopt == 'w')
				{
					print_usage(argv[0]);
					printf("-w <outfile>\n");
					exit(-1);
				}
				else
				{
					fprintf(stderr, "Invalid option %c\n", optopt);
				}
				exit(-2);

				default:
					break;	
		}
	}

	printf("Attempting to read from %s\n", file_name);
	if ((handle = pcap_open_offline(file_name,errbuf)) == NULL)
	{
		fprintf(stderr, "Error opening file %s\n", file_name);
		exit(-4);
	}
	
	pcap_loop(handle, -1, process_pkt, NULL);

	return 0;
}
