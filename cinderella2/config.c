/* $Id: config.c,v 1.2 2003/09/22 18:26:57 ak1 Exp $ */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "config.h"


/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/* XX                                                    XX */
/* XX  T H I S   C O N F I G U R A T I ON   P A R S E R  XX */
/* XX  ! ! ! ! ! ! ! ! !     S U C K S    ! ! ! ! ! ! !  XX */
/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */

static int process_tcp_config_line(char * line, int len) {
  char * module_name = NULL, * src_re = NULL, * dst_re = NULL;
  module_name = strtok(line, " ");
  src_re = strtok(NULL, " ");
  dst_re = strtok(NULL, " ");
  return add_tcp_module(module_name,src_re,dst_re);
}

static int process_udp_config_line(char * line, int len) {
  return 1;
}

static int process_icmp_config_line(char * line, int len) {

}


static int process_config_line(char * line, int len) {
  if (!line) {
    return 0;
  }

  if (strncmp(line,"tcp ",4)==0) {
    return process_tcp_config_line(line+4,len-4);
  } else if (strncmp(line,"udp ",4)==0) {
    return process_udp_config_line(line+4,len-4);
  } else if (strncmp(line,"icmp ",5)==0) {
    return process_icmp_config_line(line+5,len-5);
  } else if (line[0] == '#') {
    /* comment */
    return 1;
  }
  return 0; /* unknown line */
}

int read_config_file(char * cf) {
  int fd;
  off_t len;
  char * file, * cur;
  int retval = 1;

  if (!cf) {
    return 0;
  }

  fd = open(cf,O_RDONLY);
  if (fd<0) {
    return 0;
  }

  len = lseek(fd,0,SEEK_END);
  file = mmap(NULL,len,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);
  if (!file) {
    return 0;
  }
  
  cur = file;
  for (;;) {
    for (;cur-file < len && *cur!='\n';cur++);
    if ((++cur)-file < len) {
      char * eol;
      int line_len;
      for (eol=cur;*eol!='\n' && eol-file < len;eol++);
      if (eol-file < len) {
        *eol = '\0';
        line_len = eol-cur;
      } else {
        line_len = len - (cur-file);
      }
      if (!process_config_line(cur,line_len)) {
        retval = 0;
        break;
      }
      cur = eol+1;
    } else {
      break; /* we ran OOB, leave loop */
    }
  }

  munmap(file, len);
  close(fd);
  return retval;
}
