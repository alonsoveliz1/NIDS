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

  if((pthread_cond_init(&packet_queue.not_empty, NULL)) != 0){
    fprintf(stderr, "Failed to initialize not empty queue cond");
    pthread_mutex_destroy(&packet_queue.mutex);
    return false;
  }

  if((pthread_cond_init(&packet_queue.not_full, NULL)) != 0){
    fprintf(stderr, "Failed to initialize not_full condition\n");
    pthread_cond_destroy(&packet_queue.not_empty);
    pthread_mutex_destroy(&packet_queue.mutex);
    return false;
  }
  return true;
}

bool clean_packet_queue(void){
  pthread_mutex_lock(&packet_queue.mutex);

  while(packet_queue.count > 0){
    if(packet_queue.packets[packet_queue.tail].data != NULL){
      free(packet_queue.packets[packet_queue.tail].data);
      packet_queue.packets[packet_queue.tail].data = NULL;
    }

    packet_queue.tail = packet_queue.tail - 1;
    packet_queue.count--;
  }
 
  pthread_mutex_unlock(&packet_queue.mutex);

  pthread_cond_destroy(&packet_queue.not_full);
  pthread_cond_destroy(&packet_queue.not_empty);
  pthread_mutex_destroy(&packet_queue.mutex);

  return true;
}

bool enqueue_packet(const u_char* pkt_data, size_t len, struct timeval timestamp){
  pthread_mutex_lock(&packet_queue.mutex);
  
  // ME TENGO QUE ESPERAR A QUE NO ESTÉ LLENO SI QUIERO ENCOLAR
  while(packet_queue.count >= PACKET_QUEUE_SIZE){
    pthread_cond_wait(&packet_queue.not_full, &packet_queue.mutex);
  }

  packet_queue.packets[packet_queue.head].data = (uint8_t*)malloc(len);
  if(packet_queue.packets[packet_queue.head].data == NULL){
    pthread_mutex_unlock(&packet_queue.mutex);
    return false;
  }

  memcpy(packet_queue.packets[packet_queue.head].data, pkt_data, len);
  packet_queue.packets[packet_queue.head].len = len;
  packet_queue.packets[packet_queue.head].timestamp = timestamp;
  
  packet_queue.head = (packet_queue.head + 1);
  packet_queue.count++;
  printf("Packet_queue length %d", packet_queue.head);

  // We tell the flow manager that there are packets to process
  pthread_cond_signal(&packet_queue.not_empty);
  pthread_mutex_unlock(&packet_queue.mutex);

  return true;
}

bool dequeue_packet(packet_info_t* packet){
  pthread_mutex_lock(&packet_queue.mutex);
  
  while(packet_queue.count <= 0){
    pthread_cond_wait(&packet_queue.not_empty, &packet_queue.mutex);
  }

  packet->data = packet_queue.packets[packet_queue.tail].data;
  packet->len = packet_queue.packets[packet_queue.tail].len;
  packet->timestamp = packet_queue.packets[packet_queue.tail].timestamp;

  packet_queue.packets[packet_queue.tail].data = NULL;
  packet_queue.tail++;
  packet_queue.count--;

  pthread_cond_signal(&packet_queue.not_full);

  pthread_mutex_unlock(&packet_queue.mutex);

  return true;
}



