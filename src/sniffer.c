#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include "nids_backend.h"
#include <pthread.h>


pcap_t* pcap_handle = NULL;
//nids_config_t* config = NULL;
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
    fprintf(stderr, "(SNIFFER)[initialize_sniffer]: Error opening interface %s: %s\n", config->interface_name, errbuf);
    return false;
  }

  int datalink = pcap_datalink(pcap_handle);
  printf("(SNIFFER)[initialize_sniffer]: Link-layer header type: %d (%s)\n", datalink, pcap_datalink_val_to_name(datalink));

  struct bpf_program fp;
  char filter_exp[] = "tcp";

  if(pcap_compile(pcap_handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) != 0){
    fprintf(stderr,"(SNIFFER)[initialize_sniffer]: Error compiling berkeley-packet-filter expression\n");
    return false;
  }

  if(pcap_setfilter(pcap_handle, &fp) == -1){
    fprintf(stderr, "(SNIFFER)[initialize_sniffer]: Error setting up the filter %s\n", filter_exp);
    return false;
  }
  printf("(SNIFFER)[initialize_sniffer]: Interface: %s opened\n", config->interface_name);
  return true;
}



bool start_sniffer(void){
  if(pcap_handle == NULL){
    fprintf(stderr, "(SNIFFER)[start_sniffer]: Can't start the sniffer module cause handler is not instanciated\n");
    return false;
  }

  if(running){
    fprintf(stderr, "(SNIFFER)[start_sniffer]: Packet sniffer is already running! \n");
    return false;
  }

  running = true;

  // CODE TO START THE SNIFFER THREAD
  if(pthread_create(&sniffer_thread, NULL, &sniff_thread_func, NULL) != 0){
    fprintf(stderr, "(SNIFFER)[start_sniffer]: Sniffer thread couldn't be initialised properly\n");
    running = false;
    return false;
  }

  return true; 

}



void stop_sniffer(void){
  if(!running){
    return;
  }
  
  running = false;
  pthread_cancel(sniffer_thread);
  pthread_join(sniffer_thread, NULL); // Properly cleaning up the thread and not having a zombi process

  if(pcap_handle != NULL){
    pcap_close(pcap_handle);
    pcap_handle = NULL;
  }
  printf("(SNIFFER)[stop_sniffer]: Stopped the sniffer thread\n");
}

static void* sniff_thread_func(void* arg){
  printf("(SNIFFER)[sniff_thread_func]: Inside sniff_thread_func\n");

  if(pthread_detach(pthread_self()) != 0){
    fprintf(stderr,"(SNIFFER)[sniff_thread_func]: Wasnt detached succesfully\n");
  }

  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_setname_np(pthread_self(), "sniff_thread");
  printf("Inside the thread\n");
  /* pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) */
  pcap_loop(pcap_handle, 0, packet_handler , NULL);
  return NULL;

}


// CALLBACK FUNCTION THAT IS PROCESSED AFTER EACH RECEIVED PACKET IN PCAP_LOOP
static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
  printf("PACKET CAPTURED \n");
  if(!enqueue_packet(pkt_data, header->len, header->ts)){
    fprintf(stderr, "(SNIFFER)[packet_handler): Failed to enqueue packet\n");
  }
  // printf("(SNIFFER)[packet_handler]: Timestamp of packet in ms %ld\n", ((uint64_t)header->ts.tv_sec * 1000000 + header->ts.tv_usec));
}

 

