#include "packet.h"
#include <assert.h>
#include <stdlib.h>
#include <pcap.h>

struct packet * new_packet(const u_char * pkt, const struct pcap_pkthdr * pkthdr) {
  struct packet * p = malloc(sizeof(struct packet));
  assert(p!=NULL);

  p->packet = pkt;
  p->pkthdr = pkthdr;

  p->eth_header = (struct ether_header *)pkt;
  p->eth_payload = (pkt+sizeof(struct ether_header));
  p->eth_payload_len = pkthdr->caplen - sizeof(struct ether_header);

  p->is_ip = (p->eth_header->ether_type == ETHERTYPE_IP);

  if (p->is_ip) {
    u_char * hdr_after_ip_hdr;
    p->ip_header = (struct ip *)p->eth_payload;
    p->ip_payload = p->eth_payload + sizeof(struct ip);
    p->ip_payload_len = p->eth_payload_len - sizeof(struct ip);

    hdr_after_ip_hdr = (((u_char *)p->ip_header) + sizeof(struct ip));

    switch (p->ip_header->ip_p) {
    case IPPROTO_TCP: {
        p->tcp_header = (struct tcphdr *)hdr_after_ip_hdr;
        p->is_tcp = 1; p->is_udp = 0; p->is_icmp = 0;
        p->tcp_payload = ((u_char *)p->tcp_header)+p->tcp_header->th_off*4; /* this is sick */
        p->tcp_payload_len = p->ip_payload_len - p->tcp_header->th_off*4;
      }
      break;
    case IPPROTO_UDP: {
        p->udp_header = (struct udphdr *)hdr_after_ip_hdr;
        p->is_udp = 1; p->is_tcp = 0; p->is_icmp = 0;
        p->udp_payload = p->ip_payload + sizeof(struct udphdr);
        p->udp_payload_len = p->ip_payload_len - sizeof(struct udphdr);
      }
      break;
    case IPPROTO_ICMP: {
       p->icmp_header = (struct icmp *)hdr_after_ip_hdr;
      }
      break;
    default:
      break;
    }
  } else {
    p->ip_header = NULL;
    p->ip_payload = NULL;
    p->tcp_header = NULL;
    p->tcp_payload = NULL;
    p->udp_header = NULL;
    p->udp_payload = NULL;
    p->icmp_header = NULL;
    p->is_tcp = p->is_tcp = p->is_icmp = NULL;
  }

  return p;
}

void delete_packet(struct packet * p) {
  if (p) free(p);
}
