/* $Id: tcp_modules.c,v 1.2 2003/09/25 09:28:52 ak1 Exp $ */
#include "tcp_modules.h"

static struct tcp_module * first;

struct tcp_module * find_tcp_module(struct in_addr srcip, u_short srcport, struct in_addr dstip, u_short dstport) {
  return NULL;
}

void set_tcp_module(struct stream * s, struct tcp_module * m) {
  s->m = m;
}

int add_tcp_module(char * module, char * src_re, char * dst_re) {
  struct tcp_module * tmp = malloc(sizeof(struct tcp_module));
  if (!tmp || !module) {
    return 0;
  }
  /* TODO: load module via dlopen/dlsym */
  if (0!=regcomp(&(tmp->src_reg),src_re,REG_EXTENDED|REG_NOSUB)) {
    return 0;
  }
  if (0!=regcomp(&(tmp->dst_reg),dst_re,REG_EXTENDED|REG_NOSUB)) {
    return 0;
  }
  return 1;
}
