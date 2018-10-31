#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>   // Ethernet header
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

#define ETH_ADDR_LEN 6

//uint8_t* eth_src[ETH_ADDR_LEN];
//uint8_t* eth_dest[ETH_ADDR_LEN];
//ip_src; ip_dest
//transp protocol
//port_src; port_dest
//App Data 

struct app_pct {
	uint8_t type; // Mesage type
	uint8_t enrollment[8]; // Student ID
}__attribute__ ((packed)) ;


void print_ip(const char* pretext, uint32_t ip)
{
    printf("%s",pretext);
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

void disassemble (char *buffer, int size, char* src_mac){
    struct ether_header* eth_hdr = (struct ether_header *) buffer;
    
    if(ntohs(eth_hdr->ether_type) == ETH_P_IP){
        struct iphdr *ip_hdr = (struct iphdr *) (eth_hdr+1);
        
        if(ip_hdr->protocol == IPPROTO_UDP){
            struct udphdr *udp_hdr = (struct udphdr *)(ip_hdr+1);
            printf("%d\n",ntohs(udp_hdr->len));

            if(ntohs(udp_hdr->dest) == 1234){
                struct app_pct *app_start = (struct app_pct *)(udp_hdr+1);
            
                printf("-----------------------------------------\n");
                
                printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                    eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
                    eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]
                    );
				printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                    eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
                    eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]
                    );
                 
                print_ip("Source IP: ", ntohl(ip_hdr->saddr));
                print_ip("Destination IP: ", ntohl(ip_hdr->daddr));

                printf("Transport protocol code: %u, UDP\n",ip_hdr->protocol);

				printf("UDP source port: %u\n", ntohs(udp_hdr->source));
                printf("UDP destination port: %u\n", ntohs(udp_hdr->dest));

                printf("Packet type: %u\n", app_start->type);
                printf("Enrollment: %s\n", app_start->enrollment);
                
                if(app_start->type == 1){
                    uint16_t *name_size = ((uint16_t*) (app_start+1));
                    //printf("%lu",name_size);
                    char * student_name = (char*)(name_size+1);
                    int i;
                    printf("Student name: ");
                    for(i=0; i< *name_size; i++)
                        printf("%c",student_name[i]);
                    printf("\n");
                }
                printf("-----------------------------------------\n");
				printf("\n");
            }
        }
    }
}

int main(int argc, char **argv){    
    
	struct sockaddr socket_addr;

	unsigned char *buffer = (unsigned char *) malloc(65575); 

	int socket_raw = socket(PF_PACKET, SOCK_RAW, htons(0x0003));

	if(socket_raw < 0){
		printf("[ERROR] - Socket\n");
		return 1;
	}

	while(1){
		int socket_addr_size = sizeof(socket_addr);

		int data_size = recvfrom(socket_raw, buffer, 65575, 0, &socket_addr, &socket_addr_size);
        
		if(data_size < 0){
			printf("[ERROR] - Receiving packet\n");
			return 1;
		}

		disassemble(buffer,data_size, (char*) &socket_addr);
	}
	
    return 0;
}