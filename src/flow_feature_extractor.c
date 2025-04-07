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

int packets_processed;
pthread_t flow_manager_thread;
pthread_mutex_t flow_mutex = PTHREAD_MUTEX_INITIALIZER;
int flow_hashmap_size;

void process_packet(uint8_t* data, size_t len);
void* flow_manager_thread_func(void* arg);
u_int32_t hash_key(flow_key_t* key);
flow_stats_t* get_flow(flow_key_t* key);
flow_key_t* get_flow_key(const u_char* pkt_data, size_t len);
flow_stats_t* create_flow(flow_key_t* key);


/* Inicializa el hilo para extraer las caracteristicas de los flujos y asigna espacio en memoria para el hashmap */
bool initialize_feature_extractor(nids_config_t* session_config){
  config = session_config;
  packets_processed = 0;
  flow_hashmap_size = config->flow_table_init_size;

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

/* Lanzadera del hilo y asignacion de su funcion flow_manager_thread_func */ 
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

/* Returns a flow_key_t with processed_packet data */
flow_key_t* get_flow_key(const u_char* pkt_data, size_t len){
  /* Por ahora vamos a trabajar unicamente con paquetes IP completos, y asegurando que la trama ethernet sea de 14 bytes */
  flow_key_t* flow_key = malloc(sizeof(flow_key_t));
  if(!flow_key){
    fprintf(stderr, "[get_flow_key] Failed to allocat memory \n");
  }
  memset(flow_key, 0, sizeof(flow_key));
  
  if(len < sizeof(struct ether_header)){
    fprintf(stderr, "[get_flow_key] Packet too short for Ethernet Header\n");
    return NULL;
  }

  struct ether_header* eth_header = (struct ether_header*)pkt_data;
  printf("[DEBUG] Ethernet type: 0x%04x\n", ntohs(eth_header->ether_type));
  printf("[DEBUG] Ethernet header size: %zu bytes\n", sizeof(struct ether_header));

  if(ntohs(eth_header->ether_type) != ETHERTYPE_IP){
    fprintf(stderr, "[get_flow_key] Not an IP packet\n");
    return NULL;
  }
  const u_char* ip_packet = pkt_data + sizeof(struct ether_header);
  size_t remaining_len = len - sizeof(struct ether_header);

  if(remaining_len < sizeof(struct ip)){
    fprintf(stderr, "[get_flow_key] Packet too short for IP header");
    return NULL;
  }

  struct ip* ip_header = (struct ip*)ip_packet; 
  unsigned int ip_header_len = ip_header->ip_hl * 4;
  
  if(ip_header->ip_v != 4){
    fprintf(stderr, "[get_flow_key] Not an IPV4 packet\n");
    return NULL;
  }

    printf("[DEBUG] IP version: %u\n", ip_header->ip_v);
    printf("[DEBUG] IP header length: %u bytes\n", ip_header_len);
    printf("[DEBUG] IP total length: %u bytes\n", ntohs(ip_header->ip_len));
    printf("[DEBUG] IP protocol: %u\n", ip_header->ip_p);

  if(ip_header_len < 20 || remaining_len < ip_header_len){
    fprintf(stderr, "[get_flow_key] Invalid IP header length \n");
    return NULL;
  }

  flow_key->src_ip = ntohl(ip_header->ip_src.s_addr);
  flow_key->dst_ip = ntohl(ip_header->ip_dst.s_addr);
  flow_key->protocol = ip_header->ip_p;

  printf("[DEBUG] SRC_IP: %u (%s)\n", flow_key->src_ip, inet_ntoa(ip_header->ip_src));
  printf("[DEBUG] DST_IP: %u (%s)\n", flow_key->dst_ip, inet_ntoa(ip_header->ip_dst));

  if(flow_key->protocol == IPPROTO_TCP){
    const u_char* tcp_packet = ip_packet + ip_header_len;
    remaining_len -= ip_header_len;

    if(remaining_len < sizeof(struct tcphdr)){
      fprintf(stderr, "[get_flow_key] Packet too short for TCP header");
      return NULL;
    }

    const struct tcphdr* tcp_header = (struct tcphdr*) tcp_packet;
    flow_key->src_port = ntohs(tcp_header->source);
    flow_key->dst_port = ntohs(tcp_header->dest);
  }
  printf("[get_flow_key] PROTOCOL: %u \n", flow_key->protocol);
  printf("[get_flow_key] SRC_PORT: %u \n", flow_key->src_port);
  printf("[get_flow_key] DST_PORT: %u \n", flow_key->dst_port);

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
  flow_key_t* key = get_flow_key(data, len);
  if(!key){
    return;
  }

  flow_stats_t* flow = get_flow(key);

  if(!flow){
    flow_stats_t* created = create_flow(key);
    if(!created){
      fprintf(stderr, "[process_packet] Flow couldnt be created\n");
      return;
    }
  }
  free(key);
  packets_processed = packets_processed + 1;
  printf("[process_packet] Packets processed: %d \n", packets_processed);
}

/* Por ahora pondre uint32 */
uint32_t hash_key(flow_key_t* key){
  uint32_t hash = 0;
  hash ^= key->src_ip;
  hash ^= (uint32_t)(key->dst_ip << 1);
  hash ^= (uint32_t)(key->src_port << 8);
  hash ^= (uint32_t)(key->dst_port << 16);
  hash ^= (uint32_t)(key->protocol << 24);
  printf("[hash_key] Key %u\n", (hash % flow_hashmap_size));
  return (hash % flow_hashmap_size);

}

flow_stats_t* create_flow(flow_key_t* key){
  pthread_mutex_lock(&flow_mutex);
  uint32_t flow_hash = hash_key(key);
  
  flow_entry_t* new_entry = (flow_entry_t*)malloc(sizeof(flow_entry_t));
  if(new_entry == NULL){
    pthread_mutex_unlock(&flow_mutex);
    return NULL;
  }
  
  memset(&new_entry->stats, 0, sizeof(flow_stats_t));
  new_entry->stats.flow_hash = flow_hash;
  
  new_entry->next = flow_table[flow_hash];
  flow_table[flow_hash] = new_entry;
  
  flow_count++;

  pthread_mutex_unlock(&flow_mutex);
  return &new_entry->stats;
}

/* Por ahora vamos a pensar que ningun flujo esta en el hashmap creado y vamos a crearlo */
flow_stats_t* get_flow(flow_key_t* key){
  return NULL;
}

