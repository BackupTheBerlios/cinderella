/* $Id: tcp_modules.h,v 1.3 2003/09/25 19:09:58 ak1 Exp $ */
#ifndef TCP_MODULES_H
#define TCP_MODULES_H

#include "stream.h"

#include <sys/types.h>
#include <regex.h>

struct tcp_module {
  regex_t src_reg;
  regex_t dst_reg;
  void * eval_func;
  void * dl_handle;
  struct tcp_module * next;
};

struct tcp_module * find_tcp_module(struct in_addr srcip, u_short srcport, struct in_addr dstip, u_short dstport);

void set_tcp_module(struct stream * s, struct tcp_module * m);

int add_tcp_module(char * module, char * src_re, char * dst_re);

void init_tcp_modules(void);

#endif
