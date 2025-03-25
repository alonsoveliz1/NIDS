#include <stdio.h>
#include <pcap.h>
#include "nids_backend.h"
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

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

int get_flow_hash(const u_char* pkt_data){
  return 1;
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
  printf("Protocol %u \n", data[8]);
}
