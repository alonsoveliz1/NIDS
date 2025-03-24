#include <stdio.h>
#include <stdbool.h>
#include "nids_backend.h"
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
packet_queue_t packet_queue;

bool init_packet_queue(void){
  packet_queue.head = 0;
  packet_queue.tail = 0;
  packet_queue.count = 0;
  packet_queue.shutdown = false;

  if((pthread_mutex_init(&packet_queue.mutex, NULL)) !=0 ){
    fprintf(stderr, "Failed to initialize queue mutex\n");
    return false;
  }
  return true;
}

bool clean_packet_queue(void){
  return true;
}

bool enqueue_packet(const u_char* pkt_data, size_t len, struct timeval timestamp){
  pthread_mutex_lock(&packet_queue.mutex);

  packet_queue.packets[packet_queue.head].data = (uint8_t*)malloc(len);
  if(packet_queue.packets[packet_queue.head].data == NULL){
    pthread_mutex_unlock(&packet_queue.mutex);
    return false;
  }

  memcpy(packet_queue.packets[packet_queue.head].data, pkt_data, len);
  packet_queue.packets[packet_queue.head].len = len;
  packet_queue.packets[packet_queue.head].timestamp = timestamp;
  // THINGS TO DO
  pthread_mutex_unlock(&packet_queue.mutex);
  return true;
}

