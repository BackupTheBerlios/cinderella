/* $Id: tcp_modules.c,v 1.3 2003/09/25 19:09:58 ak1 Exp $ */
#include "tcp_modules.h"
#include <netinet/in.h> /* for ntohs(3) */
#include <stdlib.h>
#include <dlfcn.h>
#include <fmt.h>
#include <ip4.h>

static struct tcp_module * first;

void init_tcp_modules(void) {
  first = NULL;
}

struct tcp_module * find_tcp_module(struct in_addr srcip, u_short srcport, struct in_addr dstip, u_short dstport) {
  struct tcp_module * cur;
  for (cur=first;cur!=NULL;cur=cur->next) {
    char src_str[22], dst_str[22];
    char * tmp;

    /* format source ip : source port */
    tmp = src_str;
    tmp+=fmt_ip4(tmp,(const char *)(srcip.s_addr));
    tmp+=fmt_str(tmp,":");
    tmp[fmt_uint(tmp,ntohs(srcport))] = 0;

    /* format destination ip : destination port */
    tmp = dst_str;
    tmp+=fmt_ip4(tmp,(const char *)(dstip.s_addr));
    tmp+=fmt_str(tmp,":");
    tmp[fmt_uint(tmp,ntohs(dstport))] = 0;

    if (regexec(&(cur->src_reg),src_str,0,NULL,0)==0 && regexec(&(cur->dst_reg),dst_str,0,NULL,0)==0) {
      return cur;
    }

  }
  return 0;
}

void set_tcp_module(struct stream * s, struct tcp_module * m) {
  s->m = m;
}

int add_tcp_module(char * module, char * src_re, char * dst_re) {
  struct tcp_module * tmp = malloc(sizeof(struct tcp_module));
  if (!tmp || !module) {
    return 0;
  }
  tmp->dl_handle = dlopen(module,RTLD_LAZY);

  if (!tmp->dl_handle) {
    return 0;
  }

  tmp->eval_func = dlsym(tmp->dl_handle,"evaluate");

  if (!tmp->eval_func) {
    return 0;
  }

  if (0!=regcomp(&(tmp->src_reg),src_re,REG_EXTENDED|REG_NOSUB)) {
    return 0;
  }
  if (0!=regcomp(&(tmp->dst_reg),dst_re,REG_EXTENDED|REG_NOSUB)) {
    return 0;
  }

  tmp->next = first;
  first = tmp;

  return 1;
}
