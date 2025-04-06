#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#define MAX_PAYLOAD_PRINT 512

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
        return;

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_header->ip_hl * 4;
    if (ip_header_len < 20) return; 

    if (ip_header->ip_p != IPPROTO_TCP)
        return;

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
    int tcp_header_len = tcp_header->th_off * 4;
    if (tcp_header_len < 20) return;

    const u_char *payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
    int header_total_len = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - header_total_len;

    // ether Header
    printf("=== Ethernet Header ===\n");
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // IP Header
    printf("=== IP Header ===\n");
    printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

    // TCP Header
    printf("=== TCP Header ===\n");
    printf("Src Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Dst Port: %d\n", ntohs(tcp_header->th_dport));

    if (payload_len > 0) {
        printf("=== Payload (%d bytes) ===\n", payload_len > MAX_PAYLOAD_PRINT ? MAX_PAYLOAD_PRINT : payload_len);

        printf("--- ASCII ---\n");
        for (int i = 0; i < payload_len && i < MAX_PAYLOAD_PRINT; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");

        printf("--- HEX ---\n");
        for (int i = 0; i < payload_len && i < MAX_PAYLOAD_PRINT; i++) {
            printf("%02x ", payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }

    printf("========================================\n\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "\uc0ac\uc6a9\ubc95: %s <pcap \ud30c\uc77c>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        fprintf(stderr, "PCAP \ud30c\uc77c \uc5f4\uae30 \uc2e4\ud328: %s\n", errbuf);
        return 1;
    }

    printf("PCAP \ud30c\uc77c \ubd84\uc11d \uc2dc\uc791.....\n\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
