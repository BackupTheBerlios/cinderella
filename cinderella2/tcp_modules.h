#ifndef TCP_MODULES_H
#define TCP_MODULES_H

#include "stream.h"

struct tcp_module {
  void * foo;
};

struct tcp_module * find_tcp_module(struct in_addr srcip, u_short srcport, struct in_addr dstip, u_short dstport);

void set_tcp_module(struct stream * s, struct tcp_module * m);

int add_tcp_module(char * module, char * src_re, char * dst_re);


#endif
