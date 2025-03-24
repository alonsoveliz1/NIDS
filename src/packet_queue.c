#include <stdio.h>
#include <stdbool.h>
#include "nids_backend.h"
#include <stdlib.h>
packet_queue_t packet_queue;

bool init_packet_queue(void){
  return true;
}

bool clean_packet_queue(void){
  return true;
}

bool enqueue_packet(const u_char* pkt_data, size_t len, struct timeval timestamp){
  return true;
}

