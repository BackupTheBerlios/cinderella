/* $Id: process_tcp.c,v 1.2 2003/09/16 18:58:01 ak1 Exp $ */
#include "packet.h"
#include "process_tcp.h"
#include "stream.h"

void process_tcp_packet(struct packet * pkt) {
  struct stream * s;
  /* does a stream already exist? */
  if ((s = find_stream(pkt->ip_header->ip_src,pkt->tcp_header->th_sport,pkt->ip_header->ip_dst,pkt->tcp_header->th_dport))==NULL) {
    /* no -> create one */
    s = create_stream(pkt->ip_header->ip_src,pkt->tcp_header->th_sport,pkt->ip_header->ip_dst,pkt->tcp_header->th_dport);
    /* set a module for the newly created stream */
    set_module(s,find_module(pkt->ip_header->ip_src,pkt->tcp_header->th_sport,pkt->ip_header->ip_dst,pkt->tcp_header->th_dport));
  }

  if (!stream_evaluated(s)) {
    stream_add_packet(s,pkt);
    if (stream_client_closed(s) && stream_server_closed(s)) {
      stream_set_bad(s);
    } else {
      stream_try_evaluate(s);
    }

    if (stream_evaluated(s)) {
      stream_output_all(s);
    }

  } else {
    do_output_packet(s,pkt);
  }

  remove_old_streams();
}
