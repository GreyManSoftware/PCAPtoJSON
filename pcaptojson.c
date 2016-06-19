// Don't be a dick, leave this here - but use this as you see fit:)
// Chris Davies
// 89serenity@gmail.com
// git.greymansoftware.com

#include "pcaptojson.h"

int packet_count = 0;
int headerPrinted = 0;
FILE *fp;

void print_usage ()
{
	fprintf(stderr, "Usage: [-r <input_file>] [-w output_file]\n");
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
		fprintf(fp,"{\n  \"packets\":[\n");
		headerPrinted = 1;
		fprintf(fp,"    {\n");
	}
	else
	{
		fprintf(fp,",\n");
		fprintf(fp,"    {\n");
	}
	
	fprintf(fp,"     \"DateTime\":\"%ld.%06ld\",\n", packet.datetime.tv_sec, packet.datetime.tv_usec);
	fprintf(fp,"     \"src_ip\":\"%s\",\n", packet.saddr);
	fprintf(fp,"     \"dst_ip\":\"%s\",\n", packet.daddr);
	fprintf(fp,"     \"src_port\":%d,\n", packet.sport);
	fprintf(fp,"     \"dst_port\":%d,\n", packet.dport);
	fprintf(fp,"     \"NextProtocol\":%d\n", packet.proto);
	fprintf(fp,"    }");
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
					print_usage();
					exit(-1);
				}
				else if (optopt == 'w')
				{
					print_usage();
					exit(-1);
				}
				else
				{
					print_usage();
					exit(-2);
				}

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
	
	if (outfile != NULL)
		fp = fopen(outfile, "w");
	else
		fp = stdout;

	
	pcap_loop(handle, -1, process_pkt, NULL);

	fprintf(fp, "\n  ]\n}\n");
	return 0;
}
