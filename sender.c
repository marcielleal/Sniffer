/*
** Envia pacotes com o ip falso (ip spoofing)
*/
#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
//#include <net/if_arp.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <sys/types.h>
//#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <string.h>

#define MAX_ENROLL 65536

int main(int argc, char** argv){
	uint8_t pc_type = 0;
	uint16_t name_size = 0;
	char enrollment[9];
	int dataSize;


	if(argc < 2){
		printf("Missing arguments.");
		printf("The syntax of program is:\n sudo ./send enrollment [name]");
		return EXIT_FAILURE;
	}
	else{
		if(strlen(argv[1]) > 8){
			printf("The enrollment must be less than 8 bytes");
				return EXIT_FAILURE;
		}

		memset(enrollment,'\0',9);
		memcpy(enrollment,argv[1],strlen(argv[1]));

		if (argc == 2){
			pc_type = 2;
			dataSize = 1 + 8;
		}
		else if (argc == 3){
			if(strlen(argv[2]) > MAX_ENROLL){
				printf("The name must be less than 65536 bytes");
				return EXIT_FAILURE;
			}
			pc_type = 1;
			name_size = strlen(argv[2]);
			dataSize = 1 + 8 + 2 + strlen(argv[2]);
		}
		else{
			printf("Too much arguments");
			printf("The syntax of program is:\n sudo ./send enrollment [name]");
			return EXIT_FAILURE;
		}
	}
	
	
	int sockfd;
	struct sockaddr_ll param;
	int n, ifindex;
	char device[10];
	uint8_t frame[200]; //sizeof(struct arphdr)
	struct ifreq ifr;
	int tam=0;
	struct iphdr *iph;
	struct udphdr *uh;
	uint8_t *p;

	strcpy(device, "wlp7s0");

	sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP) );
	//sockfd = socket(PF_PACKET, SOCK_DGRAM, 0 );
	 
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
		fprintf(stderr, "eero: unknown iface %s\n", device);
		exit(2);
	}
	ifindex = ifr.ifr_ifindex;

	printf("ifindex=%d\n", ifindex); 

	param.sll_family = PF_PACKET;   /* Always AF_PACKET */
	param.sll_protocol = htons(ETH_P_IP); /* Physical layer protocol */
	param.sll_ifindex = ifindex;  /* Interface number */
	param.sll_hatype = 0;   /* Header type */
	param.sll_pkttype = 0;  /* Packet type */
	param.sll_halen = 6;    /* Length of address */
	memcpy(param.sll_addr, "\xaa\xaa\xaa\x00\x00\x02", 6);  /* Physical layer address(8) */

	iph = (struct iphdr *) frame;
	iph->ihl = 0x5;
	iph->version=0x4;
	iph->tos=0;
	iph->tot_len= htons(20+8+dataSize);
	iph->id=0;
	iph->frag_off=0;
	iph->ttl=0x40;
	iph->protocol=0x11; // 17 em Decimal
	iph->check=0x0;
	memcpy(&iph->saddr,"\x0a\x01\x01\x08",4); //10.1.1.8 - Pode forcar o Ip de origem
	memcpy(&iph->daddr,"\x0a\x01\x01\x01",4); //10.1.1.1

	uh = (struct udphdr *)((uint8_t *)iph + 20);
	uh->source = htons(1972);
	uh->dest = htons(1234);
	uh->len = htons(8+dataSize);
	uh->check = 0x0;

	p = (uint8_t *)uh + 8;
	
	//Data
	memcpy(p,&pc_type,1);
	p++;

	if(pc_type == 1){
		memcpy(p, enrollment,8);
		p+=8;
		memcpy(p, &name_size, 2);
		p+=2;
		memcpy(p,argv[2],name_size);
	}else if(pc_type == 2){
		memcpy(p, enrollment,8);
	}

	tam = 20 + 8 + dataSize;

	//End data

	n = sendto(sockfd, (char *)frame, tam, 0, (struct sockaddr *)&param, sizeof(param) );
	printf("n=%d\n", n);

	return(EXIT_SUCCESS);
}
