/* $Id: cind.c,v 1.4 2003/09/25 19:29:16 ak1 Exp $ */
#include <pcap.h>
#include <stdlib.h>
#include <str.h>      /* from libowfat */
#include <buffer.h>   /* from libowfat */
#include "stream.h"
#include "process.h"
#include "dumper.h"
#include "tcp_modules.h"

static void check_handle(pcap_t * h) {
  if (!h) {
    buffer_putsflush(buffer_2,"error: handle is NULL\n");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char * argv[]) {
  pcap_t * pcap_handle;
  char ebuf[PCAP_ERRBUF_SIZE];
  if (argc >= 3 && str_equal(argv[1],"-r")) {
    /* open file */
    pcap_handle = pcap_open_offline(argv[2],ebuf);
  } else {
    /* open network device */
    pcap_handle = pcap_open_live("any",65535,1,0,ebuf);
  }
  check_handle(pcap_handle);

  init_dumper(pcap_handle);
  stream_init();
  init_tcp_modules();

  pcap_loop(pcap_handle,-1,process_packet,NULL);
  exit(EXIT_SUCCESS);
}
