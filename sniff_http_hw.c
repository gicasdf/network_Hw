#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include "myheader_hw.h"

#define ETHERNET_SIZE 14  // Ethernet 헤더 크기

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // Ethernet Type이 IP 패킷인지 확인
    if (ntohs(eth->ether_type) != 0x0800) {
        return; 
    }

    struct ipheader *ip = (struct ipheader *)(packet + ETHERNET_SIZE);

    // TCP 프로토콜인지 확인
    if (ip->iph_protocol != IPPROTO_TCP) {
        return; 
    }

    // IP 헤더 길이를 계산
    int ip_header_len = ip->iph_ihl * 4; 

    struct tcpheader *tcp = (struct tcpheader *)(packet + ETHERNET_SIZE + ip_header_len);
    int tcp_header_len = (tcp->tcp_offx2 >> 4) * 4;

    // TCP Payload 시작 위치
    const u_char *payload = packet + ETHERNET_SIZE + ip_header_len + tcp_header_len;
    int payload_len = header->len - (ETHERNET_SIZE + ip_header_len + tcp_header_len);

    printf("\n================ PACKET CAPTURED ================\n");

    // Ethernet Header 출력
    printf("Ethernet Header:\n");
    printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    // IP Header 출력
    printf("IP Header:\n");
    printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    // TCP Header 출력
    printf("TCP Header:\n");
    printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

    // HTTP message 출력 (80, 443 포트 확인)
    if (payload_len > 0 && (ntohs(tcp->tcp_dport) == 80 || ntohs(tcp->tcp_dport) == 443)) {
        printf("HTTP Payload:\n");
        for (int i = 0; i < (payload_len < 100 ? payload_len : 100); i++) { // 적당한 길이 출력
            printf("%c", (payload[i] >= 32 && payload[i] <= 126) ? payload[i] : '.');
        }
        printf("\n");
    }

    printf("===============================================\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP 패킷만 캡처
    bpf_u_int32 net;

    // NIC 이름을 enp0s3으로 변경(Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    // 필터 적용(Compile filter_exp into BPF psuedo-code)
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s\n", filter_exp);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s\n", filter_exp);
        return 1;
    }

    printf("Starting packet capture...\n");

    // 패킷 캡처 시작(Capture packets)
    pcap_loop(handle, -1, got_packet, NULL);

    // 핸들 닫기
    pcap_close(handle);
    return 0;
}
