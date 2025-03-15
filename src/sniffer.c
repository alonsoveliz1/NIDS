#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include "nids_backend.h"
#include <pthread.h>

pcap_t* pcap_handle = NULL;
nids_config_t* config = NULL;
static pthread_t sniffer_thread;
bool running = false;

static void* sniff_thread_func(void* arg);
static void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);

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
  printf("Interface: %s opened\n", config->interface_name);
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

  // CODE TO START THE SNIFFER THREAD
  if(pthread_create(&sniffer_thread, NULL, &sniff_thread_func, NULL) != 0){
    fprintf(stderr, "SNIFFER.c: Sniffer thread couldn't be initialised properly\n");
    running = false;
    return false;
  }

  // TESTING IF I'M INSIDE THE THREAD
   
  int timeout = 100; // Timeout after 100 iterations
  while (timeout-- > 0) {

  usleep(1000); // Sleep for 1ms
}
  
  return true; 

}

void stop_sniffer(void){
  if(!running){
    return;
  }
  // PCAP_BREAKLOOP??
  running = false;

  // CODE TO END SNIFFER THREAD
}

static void* sniff_thread_func(void* arg){
  printf("THREAD_SNIFFER: Inside sniff_thread_func\n");

  if(pthread_detach(pthread_self()) != 0){
    fprintf(stderr,"THREAD_SNIFFER: Wasnt detached succesfully\n");
  }

  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

  printf("Inside the thread\n");
  /* pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) */
  pcap_loop(pcap_handle, 0 , packet_handler , NULL);
  return NULL;

}


// TO IMPLEMENT CALLBACK FUNCTION TO PROCCESS PACKETS
static void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet){
  printf("THREAD:INSIDE PACKET HANDLER");
  sleep(1000);
}
