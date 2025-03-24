#include <stdio.h>
#include <pcap.h>
#include "nids_backend.h"
#include <stdbool.h>
#include <stdlib.h>

typedef struct flow_entry{
  flow_stats_t stats;
  struct flow_entry* next;
} flow_entry_t;

struct flow_entry_t** flow_table = NULL;
static int flow_count = 0;
static volatile bool running = false;

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


int get_flow_hash(const u_char* pkt_data){
  return 1;
}
