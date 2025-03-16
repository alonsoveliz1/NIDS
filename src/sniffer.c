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


// CALLBACK FUNCTION THAT IS PROCESSED AFTER EACH RECEIVED PACKET IN PCAP_LOOP
static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
  printf("PACKET CAPTURED \n");
  // ESTO ES SOLO PARA PROBAR, A MI LA INFORMACION DEL PAQUETE NO ME INTERESA ALMACENARLA TENGO QUE CREAR UN FLUJO Y GUARDARME INFO
  // pcap_pkthdr {ts: timestamp, bpf_u_int32 capturelen, bpf_u_int32 len}
  char timestamp[64];
  struct tm *local_time = localtime(&header->ts.tv_sec);
  // formatting time to localtime
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);
  printf("Time: %s.%06ld\n", timestamp, header->ts.tv_usec);
  printf("Packet length: %d bytes (captured: %d bytes)\n", header->len, header->caplen);
  
  // Print protocol information (assuming Ethernet)
  // Ethernet header is 14 bytes
  if (header->caplen >= 14) {
    // Extract Ethernet type (bytes 12-13)
    uint16_t ether_type = (pkt_data[12] << 8) | pkt_data[13];
    printf("Ethernet type: 0x%04x ", ether_type);
    
    // Interpret some common Ethernet types
    switch (ether_type) {
      case 0x0800: printf("(IPv4)\n"); break;
      case 0x0806: printf("(ARP)\n"); break;
      case 0x86DD: printf("(IPv6)\n"); break;
      default: printf("(Other)\n"); break;
    }
    
    // If it's an IPv4 packet, print IP header info
    if (ether_type == 0x0800 && header->caplen >= 34) {
      // Skip Ethernet header (14 bytes) to get to IP header
      const u_char* ip_header = pkt_data + 14;
      
      // IP version and header length
      uint8_t version_ihl = ip_header[0];
      uint8_t version = (version_ihl >> 4) & 0x0F;
      uint8_t ihl = version_ihl & 0x0F;
      
      // Protocol (TCP=6, UDP=17, ICMP=1)
      uint8_t protocol = ip_header[9];
      
      // Source and destination IP
      printf("IP: v%d, Protocol: %d (", version, protocol);
      
      // Interpret protocol 
      switch (protocol) {
        case 1: printf("ICMP)\n"); break;
        case 6: printf("TCP)\n"); break;
        case 17: printf("UDP)\n"); break;
        default: printf("Other)\n"); break;
      }
      
      printf("Source IP: %d.%d.%d.%d\n", 
              ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
      printf("Dest IP: %d.%d.%d.%d\n", 
              ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
    }
  }
  printf("\n");
}
 

