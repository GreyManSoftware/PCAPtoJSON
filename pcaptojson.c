// Don't be a dick, leave this here - but use this as you see fit:)
// Chris Davies
// 89serenity@gmail.com
// git.greymansoftware.com

#include "pcaptojson.h"

int packet_count = 0;
int headerPrinted = 0;

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
	Packet PacketData;
	PacketData.datetime = header->ts;
	struct tcphdr *tcp;
	struct udphdr *udp;

	PacketData.proto = ip->protocol;
	
	strcpy(PacketData.daddr, inet_ntoa(* (struct in_addr *) &ip->daddr));
	strcpy(PacketData.saddr, inet_ntoa(* (struct in_addr *) &ip->saddr));

	//printf("%d: Proto: %d - src: %s - dst: %s - ", packet_count++, ip->protocol, PacketData.daddr, PacketData.saddr);

	switch (PacketData.proto)
	{
		case 6:
			//TCP
			tcp = (struct tcphdr *)(buffer+offset+(ip->ihl*4));
			PacketData.sport = ntohs(tcp->source);
			PacketData.dport = ntohs(tcp->dest);
			packet_to_json(PacketData);
			break;
		case 17:
			//UDP
			udp = (struct udphdr *)(buffer+offset+(ip->ihl*4));
			PacketData.sport = ntohs(udp->source);
			PacketData.dport = ntohs(udp->dest);
			packet_to_json(PacketData);
			break;
		default:
			fprintf(stderr, "Proto unknown\n");
			PacketData.sport = 0;
			PacketData.dport = 0;
			break;
	}
	
	//printf("src_port: %d - dst_port: %d\n", PacketData.sport, PacketData.dport);


}

void packet_to_json(Packet packet)
{
	if (headerPrinted == 0)
	{
		printf("{\n  \"packets\":[\n");
		headerPrinted = 1;
		printf("    {\n");
	}
	else
	{
		printf(",\n");
		printf("    {\n");
	}
	
	printf("     \"DateTime\":\"%ld.%06ld\",\n", packet.datetime.tv_sec, packet.datetime.tv_usec);
	printf("     \"src_ip\":\"%s\",\n", packet.saddr);
	printf("     \"dst_ip\":\"%s\",\n", packet.daddr);
	printf("     \"src_port\":%d,\n", packet.sport);
	printf("     \"dst_port\":%d,\n", packet.dport);
	printf("     \"NextProtocol\":%d\n", packet.proto);
	printf("    }");
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
					fprintf(stderr, "-r <file.pcap>\n");
					exit(-1);
				}
				else if (optopt == 'w')
				{
					print_usage(argv[0]);
					fprintf(stderr, "-w <outfile>\n");
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

	//printf("Attempting to read from %s\n", file_name);
	if ((handle = pcap_open_offline(file_name,errbuf)) == NULL)
	{
		fprintf(stderr, "Error opening file %s\n", file_name);
		exit(-4);
	}
	
	
	pcap_loop(handle, -1, process_pkt, NULL);

	printf("\n  ]\n}");
	return 0;
}
