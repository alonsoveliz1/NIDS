#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include "nids_backend.h"

pcap_t* pcap_handle = NULL;
nids_config_t* config = NULL;

bool running = false;
bool initialize_sniffer(nids_config_t* session_config){
  config = session_config;

  char errbuf[PCAP_ERRBUF_SIZE];
  /* Codigo para ver cuales son las interfaces de esta maquina
  pcap_if_t* devs;
  pcap_findalldevs(&devs, errbuf);
  while(devs != NULL){
    printf("%s\n",devs->name);
    devs = devs->next;
  }
  */
  pcap_handle = pcap_open_live(config->interface_name,config->bufsize, 1, 1000, errbuf);
  if(pcap_handle == NULL){
    fprintf(stderr, "Error opening interface %s: %s\n", config->interface_name, errbuf);
    return false;
  }
  printf("Interface: %s opened", config->interface_name);
  return true;
}

bool start_sniffer(void){
  if(pcap_handle == NULL){
    fprintf(stderr, "Can't start the sniffer module cause handler is not instanciated \n");
    return false;
  }

  if(running){
    fprintf(stderr, "Packet sniffer is already running! \n");
    return false;
  }
  running = true;
  return true; 

  // CODE TO START THE SNIFFER THREAD
  
}

void stop_sniffer(void){
  if(!running){
    return;
  }

  running = false;

  // CODE TO END SNIFFER THREAD
}
