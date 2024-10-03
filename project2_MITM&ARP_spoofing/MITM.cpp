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
using namespace std;

#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ETHER_HEADER_LENGTH 14
#define ETHER_ARP_LENGTH 28
#define ETHER_ARP_PACKET_LENGTH 42

#define IFNAME "ens33"
/*
[Ethernet Frame Header] [ARP Header]
---------------------------------------------------------------------------------------------------------
|Destination MAC Address (6 bytes) | Source MAC Address   (6 bytes) | Protocol Type           (2 bytes) |
---------------------------------------------------------------------------------------------------------
|Hardware Type           (2 bytes) | Protocol Type        (2 bytes) | Hardware Address Length (1 byte)  |                                 │
---------------------------------------------------------------------------------------------------------
│Protocol Address Length (1 byte)  | Operation Code       (2 bytes) │ Sender MAC Address      (6 bytes) |                                      │
---------------------------------------------------------------------------------------------------------
│Sender IP Address       (4 bytes) | Target MAC Address   (6 bytes) │ Target IP Address       (4 bytes) |                                   │
---------------------------------------------------------------------------------------------------------
*/
int packet = 0;
void print(unsigned char* ip, unsigned char* mac) {
        string mac_str = "";
        string ip_str = "";
        for (int i = 0; i < 4; i++) {
                ip_str = ip_str + to_string((unsigned int) ((unsigned char)( ip + i)));
                if (i != 3) ip_str = ip_str + ".";
        }
        printf("%s\t\t", ip_str.c_str());
        for (int i = 0; i < 6; i++) {
                mac_str = mac_str + to_string((unsigned int) ((unsigned char)( mac + i)));
                if (i != 5) mac_str = mac_str + ":";
        }
        printf("%s\n", mac_str.c_str());
}
void arp_recv(int sock_r, char* src_ip, char* buf, struct sockaddr_ll send_addr) {
	struct timeval tv = { 1, 0 };
	if (setsockopt(sock_r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		cout << "Error on recv_socket!\n";
	}
	unsigned char rbuf[80];
	while (true) {
		if (recvfrom(sock_r, rbuf, sizeof(rbuf), 0, NULL, NULL) < 0) {
			if (packet == 3) break;
			if (packet) packet += 1;
			continue;
		}
		int check = 1;
                int j = 0;
		for (int i = 38; i < 38 + 4; i++) {                                                             //38 - 42 destination ip
			if ((unsigned int) rbuf[i] != (unsigned int) (unsigned char) src_ip[j]) check = false;  //Check if the packet is for us
                        j++;
		}
		if (rbuf[31] == src_ip[3] || rbuf[31] == 1) check = 0;                                          //Check if the packet ourself or the router
		if (!check) continue;	
		if (rbuf[31] != 163) continue;
                print(rbuf + 28, rbuf + 22);                                                                    //Print the ip and mac	
                /*
		struct ether_header* eth_header = (struct ether_header*)(fak_buf);
		struct ether_arp* arp_packet = (struct ether_arp*) (fak_buf + ETHER_HEADER_LEN);
		memcpy(eth_header -> ether_dhost, rbuf + 22, ETH_ALEN);
		memcpy(arp_packet -> arp_tha, rbuf + 22, ETH_ALEN);
		memcpy(arp_packet -> arp_tpa, rbuf + 28, IP_ADDR_LEN);
                

		if (sendto(sock_r, fak_buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
			cout << "Sendto Error!\n";	
		}
                */
	}
}
/*
void arp_scan() {

	char fak[ETHER_ARP_PACKET_LENGTH];
	// Fake ARP reply
        memcpy(fak, buf, ETHER_ARP_PACKET_LEN);  
        struct ether_arp* arp_packet_fake = (struct ether_arp*) (fak + ETHER_HEADER_LEN);
        arp_packet_fake -> arp_op  = htons(ARPOP_REPLY);
        memcpy(arp_packet_fake -> arp_spa, rot_ip, IP_ADDR_LEN);


	
    for (int i = 2; i < 254; i++) {
		dst_ip[3] = i;
		memcpy(arp_packet -> arp_tpa, dst_ip, IP_ADDR_LEN);
		memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);

		if (sendto(sock_r, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
			cout << "Sendto Error!\n";	
		}
		sleep(0.5);
	}
	sleep(3);
	finish_scan = 1;
	recevier.join();

	close(sock_r);
}
*/
int main(int argc, char const *argv[]) {
        printf("Avalible devices:\n"); 
        printf("--------------------------------------\n");
        printf("IP                MAC                 \n");    
        printf("--------------------------------------\n");
        unsigned char dst_mac[MAC_LENGTH] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // Broadcast
	unsigned char src_mac[MAC_LENGTH];                                        // Source mac                              
	struct in_addr src_in_addr, dst_in_addr;                                  // Source ip, destination ip
	char dst_ip[4], src_ip[4], ap_ip[4];                                      // Destination ip, source ip, ap ip
        int index;                                                                // Interface index
        struct ifreq ifr;                                                         // Interface request
	int sd;
	if (sd = socket(AF_INET, SOCK_DGRAM, 0) < 0) {                            // Create socket
		perror("socket");
		exit(1);
	}
        strcpy(ifr.ifr_name,"ens33");                                             // Interface name
	if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) {                                   // Get source ip
		perror("ioctl");
		exit(1);
	}
	memcpy(src_ip, ifr.ifr_addr.sa_data + 2, 4);                              // Copy source ip
	if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {                                  // Get interface index
		perror("ioctl");
		exit(1);
	}
	index = ifr.ifr_ifindex;                                                  // Copy interface index
	if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {                                 // Get source mac
		perror("ioctl");
		exit(1);
	}
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);                      // Copy source mac
        for (int i = 0; i < 3; i++) {                                             // Copy destination ip
		dst_ip[i] = src_ip[i];                                            // Copy ap ip
		ap_ip[i] = src_ip[i];
	}
	ap_ip[3] = 1;                                                             
        char buf[ETHER_ARP_PACKET_LENGTH] = {0};                                   // Buffer
        struct ether_header* eth_header = (struct ether_header*) buf;              // Ethernet header
	memcpy(eth_header -> ether_dhost, dst_mac, MAC_LENGTH);                    // Copy destination mac
	memcpy(eth_header -> ether_shost, src_mac, MAC_LENGTH);                    // Copy source mac
	eth_header -> ether_type = htons(ETHERTYPE_ARP);                           // Set ether type

        struct ether_arp* arp_packet = (struct ether_arp*) malloc(ETHER_ARP_LENGTH); // ARP packet
	arp_packet -> arp_hrd = htons(ARPHRD_ETHER);                                 // Set hardware type
	arp_packet -> arp_pro = htons(ETHERTYPE_IP);                                 // Set protocol type
	arp_packet -> arp_hln = MAC_LENGTH;                                          // Set hardware length
	arp_packet -> arp_pln = IPV4_LENGTH;                                         // Set protocol length
	arp_packet -> arp_op  = htons(ARPOP_REQUEST);                                // Set opcode
	memcpy(arp_packet -> arp_sha, src_mac, MAC_LENGTH);                          // Copy source mac
	memcpy(arp_packet -> arp_tha, dst_mac, MAC_LENGTH);                          // Copy destination mac
	memcpy(arp_packet -> arp_spa, src_ip, IPV4_LENGTH);                          // Copy source ip
	memcpy(arp_packet -> arp_tpa, dst_ip, IPV4_LENGTH);                          // Copy destination ip
	memcpy(buf + ETHER_HEADER_LENGTH, arp_packet, ETHER_ARP_LENGTH);             // Copy ARP packet

        // Sockaddr
	struct sockaddr_ll send_addr;                                         
	memset(&send_addr, 0, sizeof(send_addr));
	send_addr.sll_family = AF_PACKET;
	send_addr.sll_protocol = htons(ETH_P_ARP);
	send_addr.sll_pkttype = PACKET_BROADCAST;
	send_addr.sll_ifindex = index;
	send_addr.sll_halen = 0x06;
	memset(send_addr.sll_addr, 0xff, 6);
    int sd;
	if(sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) < 0) {
                perror("socket");
                exit(1);
        }

        thread recevier(arp_recv, sock_r, src_ip, buf, send_addr);
        close(sd);
        return 0;
}	