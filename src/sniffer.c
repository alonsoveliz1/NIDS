#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include "nids_backend.h"

pcap_t* pcap_handle = NULL;
nids_config_t* config = NULL;

bool initialize_sniffer(nids_config_t* session_config){
  config = session_config;

  char errbuf[PCAP_ERRBUF_SIZE];
  int snaplen = 262144;

  pcap_handle = pcap_open_live(config->interface_name,snaplen, 1, 1000, errbuf);
  if(pcap_handle == NULL){
    fprintf(stderr, "Error opening interface %s: %s\n", config->interface_name, errbuf);
    return false;
  }
}
