/* $Id: config.c,v 1.1 2003/09/22 16:32:11 ak1 Exp $ */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "config.h"


static int process_config_file(char * line, int len) {
  if (!line) {
    return 0;
  }

}

int read_config_file(char * cf) {
  int fd;
  off_t len;
  char * file, * cur;

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
      process_config_line(cur,line_len);
      cur = eol+1;
    } else {
      break; /* we ran OOB, leave loop */
    }
  }

  munmap(file, len);
  close(fd);
  return 1;
}
