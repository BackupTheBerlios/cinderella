/* $Id: stream.h,v 1.1 2003/09/16 18:58:01 ak1 Exp $ */
#ifndef STREAM_H
#define STREAM_H

#include <sys/types.h>
#include <netinet/in.h>
#include "packet.h"

struct stream {
  struct module * m;
  u_int32_t ip_src; /* source IP */
  u_int32_t ip_dst; /* destination IP */
  u_int16_t tcp_sport; /* source IP */
  u_int16_t tcp_dport; /* destination IP */
  time_t ts;

  struct stream * next;

  /* flags: */
  int evaluated;
  int bad;
};

struct stream * find_stream(struct in_addr src_ip, u_short src_tcp, struct in_addr dst_ip, u_short dst_tcp);
struct stream * create_stream(struct in_addr src_ip, u_short src_tcp, struct in_addr dst_ip, u_short dst_tcp);

void stream_init(void);
int stream_evaluated(struct stream * s);
void stream_add_packet(struct stream * s, struct packet * p);
int stream_client_closed(struct stream * s);
int stream_server_closed(struct stream * s);
void stream_set_bad(struct stream * s);
void stream_set_good(struct stream * s);
void stream_output_all(struct stream * s);
void stream_try_evaluate(struct stream * s);
void do_output_packet(struct stream * s, struct packet * p);
void remove_old_streams(void);

#endif
