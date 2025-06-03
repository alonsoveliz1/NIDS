#include "nids_backend.h"
#include <pthread.h>
#include <string.h>

packet_queue_t packet_queue;

int init_packet_queue(){
    packet_queue.head = 0;
    packet_queue.tail = 0;
    packet_queue.count = 0;
    packet_queue.shutdown = false;

    if((pthread_mutex_init(&packet_queue.mutex, NULL)) !=0 ){
        log_error("Failed to initialize queue mutex");
        return NIDS_ERROR;
    }

    if((pthread_cond_init(&packet_queue.not_empty, NULL)) != 0){
        log_error("Failed to initialize not empty queue condition");
        pthread_mutex_destroy(&packet_queue.mutex);
        return NIDS_ERROR;
    }

    if((pthread_cond_init(&packet_queue.not_full, NULL)) != 0){
        log_error("Failed to initialize not full queue condition");
        pthread_cond_destroy(&packet_queue.not_empty);
        pthread_mutex_destroy(&packet_queue.mutex);
        return NIDS_ERROR;
    }
    return NIDS_OK;
}



int clean_packet_queue(void){

    //shutdown_packet_queue();
    //usleep(1000);

    pthread_mutex_lock(&packet_queue.mutex);

    while(packet_queue.count > 0){
        if(packet_queue.packets[packet_queue.tail].data != NULL){
              free(packet_queue.packets[packet_queue.tail].data); // Free entry
              packet_queue.packets[packet_queue.tail].data = NULL; // Avoid dangling pointer to freed data
        }

        packet_queue.tail = (packet_queue.tail + 1) % PACKET_QUEUE_SIZE;
        packet_queue.count--;
    }
 
    pthread_mutex_unlock(&packet_queue.mutex);

    pthread_cond_destroy(&packet_queue.not_full);
    pthread_cond_destroy(&packet_queue.not_empty);
    pthread_mutex_destroy(&packet_queue.mutex);

    return NIDS_OK;
}



int enqueue_packet(const u_char* pkt_data, size_t len, struct timeval timestamp){
    pthread_mutex_lock(&packet_queue.mutex);
  
    // Have to wait for queue to not be full to enqueue a packet
    while(packet_queue.count >= PACKET_QUEUE_SIZE){
        // If i'm shutting down and willing to free memory, I have to stop holding the mutex to stop any blocks
        if(packet_queue.shutdown){
            pthread_mutex_unlock(&packet_queue.mutex);
            log_info("Unlocking mutex for shutdown");
            return NIDS_ERROR;
        }

        pthread_cond_wait(&packet_queue.not_full, &packet_queue.mutex);

        if(packet_queue.shutdown){
            pthread_mutex_unlock(&packet_queue.mutex);
            log_info("Unlocking mutex for shutdown after wake up");
            return NIDS_ERROR;
        }
    }

    packet_queue.packets[packet_queue.head].data = (uint8_t*)malloc(len);
    if(packet_queue.packets[packet_queue.head].data == NULL){
          log_error("Malloc for queue position %d, failed", packet_queue.head);
          pthread_mutex_unlock(&packet_queue.mutex);
          return NIDS_ERROR;
    }

    // Fill packet_queue[head] attributes
    memcpy(packet_queue.packets[packet_queue.head].data, pkt_data, len);
    packet_queue.packets[packet_queue.head].len = len;
    packet_queue.packets[packet_queue.head].time_microseconds = (uint64_t)timestamp.tv_sec * 1000000 + timestamp.tv_usec;
    
    // Move pointer to next position
    packet_queue.head = (packet_queue.head + 1) % PACKET_QUEUE_SIZE;
    packet_queue.count++;
    log_info("Added packet to queue, curr length: %d", packet_queue.count);

    // We tell the flow manager that there are packets to process
    pthread_cond_signal(&packet_queue.not_empty);
    pthread_mutex_unlock(&packet_queue.mutex);

    return NIDS_OK;
}



int dequeue_packet(packet_info_t* packet){
  pthread_mutex_lock(&packet_queue.mutex);
  
  while(packet_queue.count <= 0){
      if (packet_queue.shutdown) {
          log_info("Shutting down the program, liberating queue mutex");
          pthread_mutex_unlock(&packet_queue.mutex);
          return NIDS_ERROR;
      }

      pthread_cond_wait(&packet_queue.not_empty, &packet_queue.mutex);

      if (packet_queue.shutdown) {
          pthread_mutex_unlock(&packet_queue.mutex);
          return NIDS_ERROR;
      }
  }

  packet->data = packet_queue.packets[packet_queue.tail].data;
  packet->len = packet_queue.packets[packet_queue.tail].len;
  packet->time_microseconds = packet_queue.packets[packet_queue.tail].time_microseconds;

  packet_queue.packets[packet_queue.tail].data = NULL;
  packet_queue.tail = (packet_queue.tail + 1) % PACKET_QUEUE_SIZE;
  packet_queue.count--;

  pthread_cond_signal(&packet_queue.not_full);
  pthread_mutex_unlock(&packet_queue.mutex);

  return NIDS_OK;
}



void shutdown_packet_queue() {
    pthread_mutex_lock(&packet_queue.mutex);
    packet_queue.shutdown = true;
    pthread_cond_broadcast(&packet_queue.not_empty);  // wake up all waiting threads
    pthread_cond_broadcast(&packet_queue.not_full);
    pthread_mutex_unlock(&packet_queue.mutex);
}

