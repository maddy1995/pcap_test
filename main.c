#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <arpa/inet.h>

void packet_check(const struct pcap_pkthdr*,const u_char*);
void packet_ip(const u_char *, int);
void packet_tcp(const u_char *, int);
void packet_eth(const u_char *, int);
void payload_data(const u_char *, int);
struct sockaddr_in source, dest;

int main(int argc, char** argv)
{
        pcap_t *handle;
        pcap_if_t *device;
        int packet_v;
        struct pacp_pkthdr* header;
        const u_char* pkt_data;
        char errbuf[100];
        char *ethname = argv[1];

        printf("%s", ethname);
        handle = pcap_open_live(ethname, 65536, 1, 0, errbuf);
	
	while(packet_v = pcap_next_ex(handle, &header,&pkt_data))
	{
        	if(packet_v == 1) packet_check(header, pkt_data);
        	if(packet_v == 0) 
		{
			printf("Timeout Error\n"); 
			return 0;
		}
        	if(packet_v == -1) continue;
        	if(packet_v == -2) 
		{
			printf("no read\n");
			return 0;
		}
    	}

	
	
        return 0;
}
void packet_check(const struct pcap_pkthdr *header, const u_char *buf)
{
                int size = header->len;

		struct ether_header * ethr = (struct ether_header*)(buf);
 
                struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
 
                packet_tcp(buf, size);
}


void packet_eth_printer(const u_char *buf, int size)
{
	struct ethhdr *eth = (struct ethhdr*)(buf);
	printf("source MAC : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("dest MAC : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);	
}

void packet_ip_printer(const u_char *buf, int size)
{
	packet_eth_printer(buf, size);
		
	struct iphdr* iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;			
		
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	char source_addr[20], dest_addr[20];
	inet_ntop(AF_INET, (void*)&source.sin_addr, source_addr, 20);
	inet_ntop(AF_INET, (void*)&dest.sin_addr, dest_addr, 20);
	printf("sorce ip: %s\n", source_addr);
	printf("dest ip: %s\n", dest_addr);
}

void packet_tcp_printer(const u_char *buf, int size)
{
	unsigned short ip_hdr_len;
	struct iphdr* iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	ip_hdr_len = iph->ihl*4;

	struct tcphdr *tcph = (struct tcphdr*)(buf + ip_hdr_len + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + ip_hdr_len + tcph->doff*4;

	packet_ip_printer(buf,size);
	printf("source tcp : %u\n", ntohs(tcph -> source));
	printf("dest tcp : %u\n" , ntohs(tcph -> dest));

	payload_data(buf + header_size, size - header_size);
}

void payload_data(const u_char* data, int size)
{
	int i, j;
	for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]);

                else printf(".");
            }
            printf("\n");
        }
        if(i%16==0) printf("   ");
        printf(" %02X",(unsigned int)data[i]);

 	if( i==size-1)
        {
            for(j=0;j<15-i%16;j++)
            {
            	printf("   ");
            }
            printf("         ");
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                 	printf("%c",(unsigned char)data[j]);
                }
                else
                {
                  printf(".");
  		}
            }
            printf( "\n" );
        }
    }
}

