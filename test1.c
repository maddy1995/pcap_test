#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
/*pcap을 이용하기 위해서 추가해준다.*/
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h> 
/*implicit declaration of function ‘inet_ntoa’이러한 오류가 떠서 arpa/inet.h를 추가해주고 주소로 지정해주는 것을 변경함.*/


#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

struct ip *iph;//ip header 구조체를 추가해줌.

typedef i_int tcp_seq;//tcp header 구조체를 추가해줌.
/*tcp를 가져오도록 구조체와 변수를 설정해줌.*/
/*tcp를 ip와 같은 방식으로 받았더니 오류나서 하나하나 다 받아서 나눠주는 방식으로 출력하려고 함.*/
const struct sniff_tcp{
	u_short th_sport;//source port
	u_short	th_dprot;//destination port
	tcp_seq th_seq; //sequence number
	tcp_seq th_ack;//sequence number
	u_char th_offx2;//data offset
	#define TH_OFF(th)   (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
 	#define TH_SYN 0x02
   	#define TH_RST 0x04
   	#define TH_PUSH 0x08
   	#define TH_ACK 0x10
   	#define TH_URG 0x20
   	#define TH_ECE 0x40
   	#define TH_CWR 0x80
   	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, 
                const u_char *packet)
/*packet을 받을 경우 함수를 호출한다.*/
	{
		static int count = 1;
    		struct ether_header *ep;
   		unsigned short ether_type;    
    		int chcnt =0;
    		int length=pkthdr->len;

    		//ethernet header를 추가해줌. 
    		ep = (struct ether_header *)packet;
		//ip를 가지고 오기 위해서 이더넷의 사이즈를 정한다고 한다.
    		packet += sizeof(struct ether_header);
		//프로토콜에 관한 내용인데 잘 모르겠음.
    		ether_type = ntohs(ep->ether_type);

    		if (ether_type == ETHERTYPE_IP)
    			{
				//ip 내용 출력
        			iph = (struct ip *)packet;
        			printf("Src Address : %s\n", inet_ntoa(*(struct in_addr *)&iph->ip_src));
        			printf("Dst Address : %s\n", inet_ntoa(*(struct in_addr *)&iph->ip_dst));

        		if (iph->ip_p == IPPROTO_TCP)
        			{
					//tcp 내용 출력
					tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
					size_tcp = TH_OFF(tcp) * 4;
            				printf("Src Port : %d\n" , ntohs(tcp->th_sport));
            				printf("Dst Port : %d\n" , ntohs(tcp->th_dport));
        			}

        		while(length--)
        			{
					//packet 내용 출력
            				printf("%02x", *(packet++)); 
            				if ((++chcnt % 16) == 0) 
                			printf("\n");
        			}
    		}
    		else
    			{
        			printf("NONE IP 패킷\n");
    			}
    			printf("\n\n");
		}    

int main(int argc, char **argv)
	{
		char *net;
    		char *mask;

    		bpf_u_int32 netp;
    		bpf_u_int32 maskp;
    		char errbuf[PCAP_ERRBUF_SIZE];
    		int ret;
    		struct pcap_pkthdr hdr;
    		struct in_addr net_addr, mask_addr;
    		struct ether_header *eptr;
    		const u_char *packet;

    		struct bpf_program fp;     

    		pcap_t *pcd;  // packet capture descriptor


    		net_addr.s_addr = netp;
    		net = inet_ntoa(*(struct in_addr *)&net_addr);
    		printf("NET : %s\n", net);

    		mask_addr.s_addr = maskp;
    		mask = inet_ntoa(*(struct in_addr *)&mask_addr);
    		printf("MSK : %s\n", mask);
    		printf("=======================\n");

    		// 디바이스 dev 에 대한 packet capture 
    		// descriptor 를얻어온다.   
   		pcd = pcap_open_live(dev, BUFSIZ,  NONPROMISCUOUS, -1, errbuf);
    		if (pcd == NULL)
    			{
        			printf("%s\n", errbuf);
        			exit(1);
    			}    

    		// 컴파일 옵션을 준다.
    		if (pcap_compile(pcd, &fp, argv[2], 0, netp) == -1)
    			{
        			printf("compile error\n");    
        			exit(1);
    			}
    		// 컴파일 옵션대로 패킷필터 룰을 세팅한다. 
    		if (pcap_setfilter(pcd, &fp) == -1)
    			{
        			printf("setfilter error\n");
        			exit(0);    
    			}

    		// 지정된 횟수만큼 패킷캡쳐를 한다. 
    		// pcap_setfilter 을 통과한 패킷이 들어올경우 
    		// callback 함수를 호출하도록 한다. 
    		pcap_loop(pcd, atoi(argv[1]), callback, NULL);
	}
