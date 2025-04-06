#include <stdio.h>
#include <pcap.h>
#include "nids_backend.h"
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
typedef struct flow_entry{
  flow_stats_t stats;
  struct flow_entry* next;
} flow_entry_t;

struct flow_entry_t** flow_table = NULL;
static int flow_count = 0;
static volatile bool running = false;

void* flow_manager_thread_func(void* arg);
pthread_t flow_manager_thread;

bool initialize_feature_extractor(nids_config_t* session_config){
  config = session_config;
  int flow_hashmap_size = config->flow_table_init_size;

  flow_table = malloc(sizeof(flow_entry_t*) * flow_hashmap_size);
  if(!flow_table){
    fprintf(stderr, "Failed to allocate flow table");
    return false;
  }

  for(int i = 0; i < flow_hashmap_size; i++){
    flow_table[i] = NULL;
  }

  flow_count = 0;
  return true; 
}

bool start_flow_manager(void){
  if(running){
    fprintf(stderr, "Flow manager is already running!\n");
    return false;
  }

  if(pthread_create(&flow_manager_thread, NULL, flow_manager_thread_func, NULL) != 0){
    fprintf(stderr, "Flow manager could not be created properly\n");
    running = false;
    return false;
  }
  running = true;
  return true;
}

flow_key_t get_flow_key(const u_char* pkt_data){
  flow_key_t flow_key;
  memset(&flow_key, 0, sizeof(flow_key));
  
  struct ether_header* eth_header = (struct ether_header*)pkt_data;
  u_char* ip_packet = pkt_data + sizeof(struct ether_header);
  
  struct ip* ip_header = (struct ip*)ip_packet;

  flow_key.src_ip = ntohl(ip_header -> ip_src.s_addr);
  flow_key.dst_ip = ntohl(ip_header->ip_dst.s_addr);
  flow_key.protocol = ip_header->ip_p;

  unsigned int ihl = ip_header->ip_hl;

  u_char* tcp_packet = ip_packet + ihl * 4;
  if(flow_key.protocol == IPPROTO_TCP){
    struct tcphdr* tcp_header = (struct tcphdr*) tcp_packet;
    flow_key.src_port = tcp_header->th_sport;
    flow_key.dst_port = tcp_header->th_dport;
  }
  printf("[get_flow_key] SRC_IP: %u \n", flow_key.src_ip);
  printf("[get_flow_key] DST_IP: %u \n", flow_key.dst_ip);
  printf("[get_flow_key] PROTOCOL: %u \n", flow_key.protocol);
  printf("[get_flow_key] SRC_PORT: %u \n", flow_key.src_port);
  printf("[get_flow_key] DST_PORT: %u \n", flow_key.dst_port);


   return flow_key;
}

void stop_flow_manager(void){
  if(!running){
    fprintf(stderr, "Flow manager aint running");
  }

  running = false;
  pthread_cancel(flow_manager_thread);
  printf("FLOW_MANAGER_THREAD: Stopped the flow_manager_thread");
}


void* flow_manager_thread_func(void* arg){
  packet_info_t packet;

  printf("THREAD_FEATURE_EXTRACTOR: Inside flow_manager_thread_func\n");

  if(pthread_detach(pthread_self()) != 0){
    fprintf(stderr, "THREAD_FEATURE_EXTRACOTR: Wasnt detached successfully\n");
  }

  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_setname_np(pthread_self(), "flow_mngr_thread");
  
  while(running){
    if(dequeue_packet(&packet)){
      process_packet(packet.data, packet.len);
    }
  }
  return NULL;
}

void process_packet(u_int8_t* data, size_t len){
  flow_key_t key = get_flow_key(data);
  
}


