#ifndef PACKET_H
#define PACKET_H

#include <sys/types.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <net/ethernet.h> /* seems to exist on Linux and OSX */
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

struct packet {
  /* flags marking the protocol types */
  int is_ip;
  int is_tcp;
  int is_udp;
  int is_icmp;

  /* the information that we got from libpcap */
  const u_char * packet;
  const struct pcap_pkthdr * pkthdr;


  /* preprocessed information */
  struct ether_header * eth_header;
  const u_char * eth_payload;
  unsigned int eth_payload_len;

  struct ip * ip_header;
  const u_char * ip_payload;
  unsigned int ip_payload_len;

  struct tcphdr * tcp_header;
  const u_char * tcp_payload;
  unsigned int tcp_payload_len;

  struct udphdr * udp_header;
  const u_char * udp_payload;
  unsigned int udp_payload_len;

  struct icmp * icmp_header;

};

struct packet * new_packet(const u_char * pkt, const struct pcap_pkthdr * );

void delete_packet(struct packet * p);


#endif
