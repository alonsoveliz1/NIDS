#ifndef NIDS_BACKEND_H
#define NIDS_BACKEND_H

#include <stdbool.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct{
  char* interface_name;
  int bufsize;
  int flow_table_init_size;
} nids_config_t;

extern nids_config_t* config;

typedef struct{
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
  //ISN del flujo para identificarlo
} flow_key_t;

/* Here will go all the features my model needs to class¡fy */
typedef struct{
  uint32_t flow_hash;
  u_int32_t packets_processed;
  u_int32_t bytes_processed;

} flow_stats_t;

typedef struct {
  uint8_t* data;
  size_t len;
  struct timeval timestamp;
} packet_info_t;

#define PACKET_QUEUE_SIZE 10

typedef struct{
  packet_info_t packets[PACKET_QUEUE_SIZE];
  int head;
  int tail;
  int count;
  pthread_mutex_t mutex;
  pthread_cond_t not_empty;
  pthread_cond_t not_full;
  bool shutdown;
} packet_queue_t;

/* Inicializacion del sistema */
bool init_nids(nids_config_t* config);
/* Terminacion del sistema */ 

/* Initialization sniffer */
bool initialize_sniffer(nids_config_t* config);
/* Terminacion del sniffer */

bool start_sniffer(void);
void stop_sniffer(void);
//static void pcap_handler(u_char* user, const struct pcap_pkthdsh r* h, const u_char* bytes);

bool initialize_feature_extractor(nids_config_t*);


bool enqueue_packet(const u_char* pkt_data, size_t len, struct timeval timestamp);
bool dequeue_packet(packet_info_t* packet);
#endif /*NIDS_BACKEND_H */
