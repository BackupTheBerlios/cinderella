/* $Id: process.c,v 1.1 2003/09/15 20:03:19 ak1 Exp $ */
#include <pcap.h>
#include "packet.h"

#include "process.h"
#include "process_tcp.h"
#include "process_udp.h"
#include "process_icmp.h"
#include "process_other.h"


void process_packet(u_char * user, const struct pcap_pkthdr * pkthdr, const u_char * pkt) {
  struct packet * packet = new_packet(pkt,pkthdr);
  if (packet->is_ip) {
    if (packet->is_tcp) {
      process_tcp_packet(packet);
    } else if (packet->is_udp) {
      process_udp_packet(packet);
    } else if (packet->is_icmp) {
      process_icmp_packet(packet);
    } else {
      process_other_packet(packet);
    }
  } else {
    process_other_packet(packet);
  }
}
