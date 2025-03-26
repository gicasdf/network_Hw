#ifndef MYHEADER_H
#define MYHEADER_H

#include <stdint.h>
#include <netinet/in.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];  /* destination host address */
    u_char  ether_shost[6];  /* source host address */
    u_short ether_type;      /* protocol type */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, /* IP header length */
                       iph_ver:4; /* IP version */
    unsigned char      iph_tos;   /* Type of service */
    unsigned short int iph_len;   /* Total length */
    unsigned short int iph_ident; /* Identification */
    unsigned short int iph_flag:3, /* Flags */
                       iph_offset:13; /* Fragment offset */
    unsigned char      iph_ttl;   /* Time to Live */
    unsigned char      iph_protocol; /* Protocol */
    unsigned short int iph_chksum; /* Checksum */
    struct in_addr     iph_sourceip; /* Source IP */
    struct in_addr     iph_destip;   /* Destination IP */
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;   /* source port */
    u_short tcp_dport;   /* destination port */
    u_int   tcp_seq;     /* sequence number */
    u_int   tcp_ack;     /* acknowledgement number */
    u_char  tcp_offx2;   /* data offset */
    u_char  tcp_flags;   /* flags */
    u_short tcp_win;     /* window */
    u_short tcp_sum;     /* checksum */
    u_short tcp_urp;     /* urgent pointer */
};

#endif /* MYHEADER_H */
