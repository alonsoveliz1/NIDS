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

typedef struct{
  uint16_t flow_hash;
} flow_stats_t;

typedef struct{
  int head;
  int tail;
  int count;
} packet_queue_t;

/* Inicializacion del sistema */
bool init_nids(nids_config_t* config);
/* Terminacion del sistema */ 

/* Initialization sniffer */
bool initialize_sniffer(nids_config_t* config);
/* Terminacion del sniffer */

bool start_sniffer(void);
void stop_sniffer(void);
//static void pcap_handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes);

bool initialize_feature_extractor(nids_config_t*);


bool enqueue_packet(const u_char* pkt_data, size_t len, struct timeval timestamp);
#endif /*NIDS_BACKEND_H */
