/* $Id: stream.c,v 1.1 2003/09/16 18:58:01 ak1 Exp $ */
#include <stdlib.h>
#include "stream.h"


static struct stream * first, * last;

void stream_init(void) {
  first = last = NULL;
}

struct stream * find_stream(struct in_addr src_ip, u_short src_tcp, struct in_addr dst_ip, u_short dst_tcp) {
  struct stream * cur = first;
  for (;cur!=NULL;cur=cur->next) {

    if (cur->ip_src == src_ip.s_addr && cur->tcp_sport == src_tcp && cur->ip_dst == dst_ip.s_addr && cur->tcp_dport == dst_tcp) {
      return cur;
    }

    if (cur->ip_src == dst_ip.s_addr && cur->tcp_sport == dst_tcp && cur->ip_dst == src_ip.s_addr && cur->tcp_dport == src_tcp) {
      return cur;
    }

  }
  return NULL; /* shouldn't happen */
}
