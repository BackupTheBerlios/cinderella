/* $Id: cind.c,v 1.2 2003/09/22 18:26:57 ak1 Exp $ */
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include "stream.h"
#include "process.h"
#include "dumper.h"

static void check_handle(pcap_t * h) {
  if (!h) {
    fprintf(stderr,"error: handle is NULL\n");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char * argv[]) {
  pcap_t * pcap_handle;
  char ebuf[PCAP_ERRBUF_SIZE];
  if (argc >= 3 && strcmp(argv[1],"-r")==0) {
    /* open file */
    pcap_handle = pcap_open_offline(argv[2],ebuf);
  } else {
    /* open network device */
    pcap_handle = pcap_open_live("any",65535,1,0,ebuf);
  }
  check_handle(pcap_handle);

  init_dumper(pcap_handle);
  stream_init();

  pcap_loop(pcap_handle,-1,process_packet,NULL);
  exit(EXIT_SUCCESS);
}
