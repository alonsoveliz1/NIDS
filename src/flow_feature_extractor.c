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
#include <stdbool.h>

typedef struct flow_entry{
  flow_stats_t stats;
  struct flow_entry* next;
} flow_entry_t;

typedef enum{
  FWD = 1,
  BWD = 2
} flow_direction_t;

struct flow_entry** flow_table = NULL;
static int flow_count = 0;
static volatile bool running = false;

int packets_processed;
pthread_t flow_manager_thread;
pthread_mutex_t flow_mutex = PTHREAD_MUTEX_INITIALIZER;
int flow_hashmap_size;

void process_packet(uint8_t* data, size_t len, uint64_t time_microseconds);
void* flow_manager_thread_func(void* arg);
u_int32_t hash_key(flow_key_t* key);
flow_stats_t* get_flow(flow_key_t* key, uint32_t flow_hash);
flow_key_t* get_flow_key(const u_char* pkt_data, size_t len);
flow_stats_t* create_flow(flow_key_t* key, uint32_t flow_hash, u_char* data, size_t len, uint64_t time_microseconds);
flow_stats_t* update_flow(flow_key_t* key, flow_stats_t* flow, u_char* data, size_t len, uint64_t time_microseconds);


uint8_t get_tcp_flags(u_char* data, size_t len);
uint32_t get_header_len(u_char* data, size_t len);
uint32_t get_tcp_window_size(u_char* data, size_t len);
flow_direction_t get_packet_direction(flow_stats_t* flow, flow_key_t* key);

/* Inicializa el hilo para extraer las caracteristicas de los flujos y asigna espacio en memoria para el hashmap */
bool initialize_feature_extractor(nids_config_t* session_config){
    if(!session_config){
        fprintf(stderr, "ERROR (FFEXTR)[init_ffextr]: Null session_config ptr");
        return false;
  }
    config = session_config;
    packets_processed = 0;
    flow_hashmap_size = config->flow_table_init_size;

    flow_table = malloc(sizeof(flow_entry_t*) * flow_hashmap_size);
    if(!flow_table){
        fprintf(stderr, "(FFEXTR)[initialize_feature_extractor]: Failed to allocate flow table");
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
        fprintf(stderr, "(FFEXTR)[start_flow_manager]: Flow manager is already running!\n");
        return false;
    }

    if(pthread_create(&flow_manager_thread, NULL, flow_manager_thread_func, NULL) != 0){
        fprintf(stderr, "(FFEXTR)[start_flow_manager]: Flow manager could not be created properly\n");
        running = false;
        return false;
    }
    running = true;
    return true;
  }

/* Returns a flow_key_t with processed_packet data */
flow_key_t* get_flow_key(const u_char* pkt_data, size_t len){
    if(!pkt_data){
        fprintf(stderr, "ERROR (FFEXTR)[get_flow_key] NULL pkt_data ptr");
        return NULL;
    }
  /* Por ahora vamos a trabajar unicamente con paquetes IP completos, y asegurando que la trama ethernet sea de 14 bytes */
    flow_key_t* flow_key = malloc(sizeof(flow_key_t));
    if(!flow_key){
        fprintf(stderr, "(FFEXTR)[get_flow_key]: Failed to allocat memory \n");
    }
    memset(flow_key, 0, sizeof(flow_key_t));
  
    if(len < sizeof(struct ether_header)){
        fprintf(stderr, "(FFEXTR)[get_flow_key]: Packet too short for Ethernet Header\n");
        free(flow_key);
        return NULL;
    }

    struct ether_header* eth_header = (struct ether_header*)pkt_data;
    // printf("(FFEXTR)[get_flow_key] Ethernet type: 0x%04x\n", ntohs(eth_header->ether_type));
    printf("(FFEXTR)[get_flow_key] Ethernet header size: %zu bytes\n", sizeof(struct ether_header));

    if(ntohs(eth_header->ether_type) != ETHERTYPE_IP){
        fprintf(stderr, "(FFEXTR)[get_flow_key]: Not an IP packet\n");
        free(flow_key);
        return NULL;
    }
    const u_char* ip_packet = pkt_data + sizeof(struct ether_header);
    size_t remaining_len = len - sizeof(struct ether_header);

    if(remaining_len < sizeof(struct ip)){
        fprintf(stderr, "(FFEXTR)[get_flow_key]: Packet too short for IP header");
        free(flow_key);
        return NULL;
    }

    struct ip* ip_header = (struct ip*)ip_packet; 
    unsigned int ip_header_len = ip_header->ip_hl * 4;
  
    if(ip_header->ip_v != 4){
        fprintf(stderr, "(FFEXTR)[get_flow_key] Not an IPV4 packet\n");
        free(flow_key);
        return NULL;
    }

    // printf("(FFEXTR)[get_flow_key] IP version: %u\n", ip_header->ip_v);
    printf("(FFEXTR)[get_flow_key] IP header length: %u bytes\n", ip_header_len);
    printf("(FFEXTR)[get_flow_key] IP total length: %u bytes\n", ntohs(ip_header->ip_len));
    // printf("(FFEXTR)[get_flow_key] IP protocol: %u\n", ip_header->ip_p);

    if(ip_header_len < 20 || remaining_len < ip_header_len){
        fprintf(stderr, "(FFEXTR)[get_flow_key]: Invalid IP header length \n");
        free(flow_key);
        return NULL;
    }

    flow_key->src_ip = ntohl(ip_header->ip_src.s_addr);
    flow_key->dst_ip = ntohl(ip_header->ip_dst.s_addr);
    flow_key->protocol = ip_header->ip_p;

    printf("(FFEXTR)[get_flow_key] SRC_IP: %u (%s)\n", flow_key->src_ip, inet_ntoa(ip_header->ip_src));
    printf("(FFEXTR)[get_flow_key] DST_IP: %u (%s)\n", flow_key->dst_ip, inet_ntoa(ip_header->ip_dst));

    if(flow_key->protocol == IPPROTO_TCP){
        const u_char* tcp_packet = ip_packet + ip_header_len;
        remaining_len -= ip_header_len;

        if(remaining_len < sizeof(struct tcphdr)){
            fprintf(stderr, "ERROR (FFEXTR)[get_flow_key]: Packet too short for TCP header");
            free(flow_key);
            return NULL;
        }

        const struct tcphdr* tcp_header = (struct tcphdr*) tcp_packet;
        flow_key->src_port = ntohs(tcp_header->source);
        flow_key->dst_port = ntohs(tcp_header->dest);
    }
    // printf("DEBUG (FFEXTR)[get_flow_key] PROTOCOL: %u \n", flow_key->protocol);
    printf("DEBUG (FFEXTR)[get_flow_key] SRC_PORT: %u \n", flow_key->src_port);
    printf("DEBUG (FFEXTR)[get_flow_key] DST_PORT: %u \n", flow_key->dst_port);

   return flow_key;
  }

void stop_flow_manager(void){
    if(!running){
        fprintf(stderr, "ERROR (FFEXTR)[stop_flow_manager] Flow manager aint running");
    }

    running = false;
    pthread_cancel(flow_manager_thread);
    printf("DEBUG (FFEXTR)[stop_flow_manager]: Stopped the flow_manager_thread");
  }


void* flow_manager_thread_func(void* arg){
    packet_info_t packet;

    printf("DEBUG (FFEXTR)[flow_manager_thread_func]: Inside flow_manager_thread_func\n");

    if(pthread_detach(pthread_self()) != 0){
        fprintf(stderr, "ERROR (FFEXTR)[flow_manager_thread_func]: Wasnt detached successfully\n");
    }

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setname_np(pthread_self(), "flow_mngr_thread");
  
    while(running){
        if(dequeue_packet(&packet)){
            process_packet(packet.data, packet.len, packet.time_microseconds);
        }
    }
    return NULL;
  }

void process_packet(uint8_t* data, size_t len, uint64_t time_microseconds){
    if(!data){
        fprintf(stderr, "ERROR (FFEXTR)[process_packet] NULL data ptr");
        return;
    }

    flow_key_t* key = get_flow_key(data, len);
    if(!key){
        printf("ERROR (FFEXTR)[process_packet] Key couldnt be computed \n");
        return;
    }
    u_int32_t flow_hash = hash_key(key);
    if(flow_hash == UINT32_MAX){
        fprintf(stderr, "ERROR (FFEXTR)[process_packet] Flow hash couldnt be computed properly \n");
        return;
    }
    flow_stats_t* existing_flow = get_flow(key, flow_hash);
    if(!existing_flow){
        flow_stats_t* created = create_flow(key, flow_hash, data, len, time_microseconds);
        if(!created){
            fprintf(stderr, "(FFEXTR)[process_packet] Flow couldnt be created\n");
            return;
        }
        printf("Flow %u created\n", flow_hash);
    } else {
        flow_stats_t* updated = update_flow(key, existing_flow, data, len, time_microseconds);
        if(!updated){
            fprintf(stderr, "(FFEXTR)[process_packet] Flow couldnt be updated\n");
            return;
        } else {
            printf("(FFEXTR)[process_packet] Flow was updated successfully\n");
          }
      }

    free(key);
    packets_processed = packets_processed + 1;
    printf("(FFEXTR)[process_packet] Packets processed: %d \n", packets_processed);
  }

/* Por ahora pondre uint32. No puedo shiftear src_port y dst_port una cantidad de bits diferentes, 
 * porque sino los paquetes flow_manager_thread_funcy bwd se interpretarian como flujos distintos */
uint32_t hash_key(flow_key_t* key) {
    if(!key){
        fprintf(stderr, "ERROR (FFEXTR)[hash_key] NULL key ptr");
        return UINT32_MAX;
    }
    uint32_t hash = 0;
  
    // Lower IP && port first to get same hash in both directions 
    uint32_t ip_a, ip_b;
    uint16_t port_a, port_b;
  
    if (key->src_ip < key->dst_ip || (key->src_ip == key->dst_ip && key->src_port < key->dst_port)) {
        ip_a = key->src_ip;
        ip_b = key->dst_ip;
        port_a = key->src_port;
        port_b = key->dst_port;
    } else {
        ip_a = key->dst_ip;
        ip_b = key->src_ip;
        port_a = key->dst_port;
        port_b = key->src_port;
    }
  
    hash ^= ip_a;
    hash ^= (ip_b << 1);
    hash ^= ((uint32_t)port_a << 8);
    hash ^= ((uint32_t)port_b << 8);
    hash ^= ((uint32_t)key->protocol << 24);
  
    return (hash % flow_hashmap_size);
  }

/* Allocates memory for a new_flow entry, sets flow hash as the key to the flow_table and the flow to the head of its bucket of the linked list */
flow_stats_t* create_flow(flow_key_t* key, uint32_t flow_hash, u_char* data, size_t len, uint64_t time_microseconds){
    if(!key || !data){
        fprintf(stderr, "ERROR (FFEXTR)[create_flow] NULL key or data ptr");
        return NULL;
    }
    pthread_mutex_lock(&flow_mutex);
  
    flow_entry_t* new_entry = (flow_entry_t*)malloc(sizeof(flow_entry_t));
    if(new_entry == NULL){
        fprintf(stderr, "ERROR (FFEXTR)[create_flow]: Failed to allocate memory for new flow entry\n");
        pthread_mutex_unlock(&flow_mutex);
        return NULL;
    }
  
    memset(&new_entry->stats, 0, sizeof(flow_stats_t));
    memcpy(&new_entry->stats.key, key, sizeof(flow_key_t));

    new_entry->stats.expired = false;
    new_entry->stats.idle_time = 0;

    new_entry->stats.dst_ip_fwd = key->dst_ip;
    new_entry->stats.flow_hash = flow_hash;
  
    new_entry->stats.flow_start_time = time_microseconds;
    new_entry->stats.flow_last_time = time_microseconds;
    new_entry->stats.flow_duration = 0;
    //printf("DEBUG (FFEXTR)[create_flow] Fow_start_time : %ld\n", new_entry->stats.flow_start_time);
  
    new_entry->stats.total_fwd_packets = 1;
    new_entry->stats.total_bwd_packets = 0;
  
    new_entry->stats.total_fwd_bytes = len;
    new_entry->stats.total_bwd_bytes = 0;

    new_entry->stats.fwd_packet_len_min = len;
    new_entry->stats.fwd_packet_len_max = len;
    new_entry->stats.fwd_packet_len_mean = len;
    new_entry->stats.fwd_packet_len_std = len;

    new_entry->stats.bwd_packet_len_min = UINT16_MAX;
    new_entry->stats.bwd_packet_len_max = len;
    new_entry->stats.bwd_packet_len_mean = len;
    new_entry->stats.bwd_packet_len_std = 0;

    new_entry->stats.flow_bytes_per_sec = len;
    new_entry->stats.flow_packets_per_sec = 1;

    new_entry->stats.flow_iat_mean = 0;
    new_entry->stats.flow_iat_std = 0;
    new_entry->stats.flow_iat_max = 0;
    new_entry->stats.flow_iat_min = UINT64_MAX;
    new_entry->stats.flow_iat_total = 0;

    new_entry->stats.fwd_iat_min = UINT64_MAX;
    new_entry->stats.fwd_iat_max = 0;
    new_entry->stats.fwd_iat_mean = 0;
    new_entry->stats.fwd_iat_std = 0;
    new_entry->stats.fwd_iat_total = 0;

    new_entry->stats.bwd_iat_min = UINT64_MAX;
    new_entry->stats.bwd_iat_max = 0;
    new_entry->stats.bwd_iat_mean = 0;
    new_entry->stats.bwd_iat_std = 0;
    new_entry->stats.bwd_iat_total = 0;

    uint8_t tcp_flags = get_tcp_flags(data, len);
    new_entry->stats.fwd_psh_flags = (tcp_flags & TH_PUSH) ? 1 : 0;
    new_entry->stats.bwd_psh_flags = 0;
    new_entry->stats.fwd_urg_flags = (tcp_flags & TH_URG) ? 1 : 0;
    new_entry->stats.bwd_urg_flags = 0;

    uint32_t header_length = get_header_len(data, len);
    new_entry->stats.fwd_header_len = header_length;
    new_entry->stats.bwd_header_len = 0;

    new_entry->stats.fwd_packets_per_sec = 1;
    new_entry->stats.bwd_packets_per_sec = 0;

    new_entry->stats.packet_len_min = len;
    new_entry->stats.packet_len_max = len;
    new_entry->stats.packet_len_mean = len;
    new_entry->stats.packet_len_std = 0;
    new_entry->stats.packet_len_variance = 0;

    new_entry->stats.fin_flag_count = (tcp_flags & TH_FIN) ? 1 : 0;
    new_entry->stats.syn_flag_count = (tcp_flags & TH_SYN) ? 1: 0;
    new_entry->stats.rst_flag_count = (tcp_flags & TH_RST) ? 1: 0;
    new_entry->stats.psh_flag_count = (tcp_flags & TH_PUSH) ? 1: 0;
    new_entry->stats.ack_flag_count = (tcp_flags & TH_ACK) ? 1 : 0;
    new_entry->stats.urg_flag_count = (tcp_flags & TH_URG) ? 1 : 0;
    new_entry->stats.cwr_flag_count = (tcp_flags & 0x80) ? 1 : 0; //0x80 CWR flag mi sistema no lo tiene  
    new_entry->stats.ece_flag_count = (tcp_flags & 0x40) ? 1 : 0; //0x40 ECE flag lo mismo
  
    new_entry->stats.down_up_ratio = 0;
    new_entry->stats.avg_packet_size = len;
    size_t packet_size = len - header_length;
    new_entry->stats.fwd_segment_size_avg = packet_size; // Tamaño segmento = paquete - cabeceras
    new_entry->stats.bwd_segment_size_avg = 0;
    new_entry->stats.fwd_segment_size_tot = packet_size;
    new_entry->stats.bwd_segment_size_tot = 0;
    new_entry->stats.fwd_seg_size_min = packet_size;

    if(packet_size > 100){
        new_entry->stats.last_fwd_packet_is_bulk = true;
        new_entry->stats.fwd_bulk_start = time(NULL);
        new_entry->stats.num_fwd_bulk_transmissions = 1;
        new_entry->stats.fwd_bytes_bulk_tot = packet_size;
        new_entry->stats.fwd_packet_bulk_tot = 1;
        new_entry->stats.fwd_bytes_bulk_avg = packet_size;
        new_entry->stats.fwd_packet_bulk_avg = 1;
        new_entry->stats.fwd_bulk_rate_avg = packet_size;
    
    } else {
        new_entry->stats.last_fwd_packet_is_bulk = false;
        new_entry->stats.fwd_bulk_start = time(NULL);
        new_entry->stats.num_fwd_bulk_transmissions = 0;
        new_entry->stats.fwd_bytes_bulk_avg = 0;
        new_entry->stats.fwd_packet_bulk_avg = 0;
        new_entry->stats.fwd_bulk_rate_avg = 0;
        new_entry->stats.fwd_bytes_bulk_tot = 0;
        new_entry->stats.fwd_packet_bulk_tot = 0;
  }
  
    new_entry->stats.last_bwd_packet_is_bulk = false;
    new_entry->stats.num_bwd_bulk_transmissions = 0;
    new_entry->stats.bwd_bytes_bulk_tot = 0;
    new_entry->stats.bwd_packet_bulk_tot = 0;
    new_entry->stats.bwd_bytes_bulk_avg = 0;
    new_entry->stats.bwd_packet_bulk_avg = 0;
    new_entry->stats.bwd_bulk_rate_avg = 0;

    new_entry->stats.subflow_fwd_packets = 0;
    new_entry->stats.subflow_fwd_bytes = 0;
    new_entry->stats.subflow_bwd_packets = 0;
    new_entry->stats.subflow_bwd_bytes = 0;

    uint32_t init_win_bytes = get_tcp_window_size(data,len);
    new_entry->stats.fwd_init_win_bytes = init_win_bytes;
    new_entry->stats.bwd_init_win_bytes = 0;
    new_entry->stats.fwd_act_data_packets = (packet_size > 1) ? 1 : 0;
  
    new_entry->stats.active_min = 0;
    new_entry->stats.active_mean = 0;
    new_entry->stats.active_max = 0;
    new_entry->stats.active_std = 0;

    new_entry->stats.idle_min = 0;
    new_entry->stats.idle_mean = 0;
    new_entry->stats.idle_max = 0;
    new_entry->stats.idle_std = 0;

    // Apunto al anterior flujo que tenia ese hash
    new_entry->next = flow_table[flow_hash];
    // Ahora la key del hashmap es el nuevo flujo que encabeza la linked_list
    flow_table[flow_hash] = new_entry;
  
    flow_count++;

    pthread_mutex_unlock(&flow_mutex);
    return &new_entry->stats;
  }

flow_stats_t* get_flow(flow_key_t* key, uint32_t flow_hash){
    if(!key){
        fprintf(stderr, "ERROR (FFEXTR)[get_flow] NULL key ptr");
        return NULL;
    }
    pthread_mutex_lock(&flow_mutex);
  
    flow_entry_t* current_flow = flow_table[flow_hash];

    while(current_flow != NULL){
        if(current_flow->stats.key.src_ip == key->src_ip && current_flow->stats.key.dst_ip == key->dst_ip && 
            current_flow->stats.key.src_port == key->src_port && current_flow->stats.key.dst_port == key->dst_port &&
            current_flow->stats.key.protocol == key->protocol) 
        {
                pthread_mutex_unlock(&flow_mutex);
                return &current_flow->stats;
        }

        if(current_flow->stats.key.src_ip == key->dst_ip && current_flow->stats.key.dst_ip == key->src_ip &&
            current_flow->stats.key.src_port == key->dst_port && current_flow->stats.key.dst_port == key->src_port && 
            current_flow->stats.key.protocol == key->protocol)
        {
                pthread_mutex_unlock(&flow_mutex);
                return &current_flow->stats;
        }
        current_flow = current_flow->next;
    }
    pthread_mutex_unlock(&flow_mutex);
    return NULL;
  }


flow_stats_t* update_flow(flow_key_t* key, flow_stats_t* flow, u_char* data, size_t len, uint64_t time_microseconds){
    pthread_mutex_lock(&flow_mutex);
    if(!key || !flow || !data){
        fprintf(stderr, "ERROR (FFEXTR)[get_packet_direction]: NULL Pointer received\n");
        return NULL;
    }

    uint64_t iat = time_microseconds - flow->flow_last_time;
    flow_direction_t packet_direction = get_packet_direction(flow, key);
    // printf("Flow direction of packet %d\n", packet_direction);
    uint8_t tcp_flags = get_tcp_flags(data, len);
    uint32_t header_length = get_header_len(data, len);
    size_t packet_size = len - header_length;
    uint32_t win_bytes = get_tcp_window_size(data,len);

    flow->idle_time = time_microseconds - flow->flow_last_time; // If I get a packet iat == idle_time
    if(flow->idle_time >= 120000000){ // 120 seconds w/o packets -> expired
        flow->expired = true;
    }

    flow->flow_last_time = time_microseconds; // Now we can update flow_last_time
    flow->flow_duration = flow->flow_last_time - flow->flow_start_time; 
  
    // Update flow IAT
    flow->flow_iat_total += iat;
    (iat > flow->flow_iat_max) ? flow->flow_iat_max = iat : (void)0;
    (iat < flow->flow_iat_min) ? flow->flow_iat_min = iat : (void)0;

    // Update packet len Min & Max
    (flow->packet_len_min < len) ? flow->packet_len_min = len : (void)0;
    (flow->packet_len_max < len) ? flow->packet_len_max = len : (void)0;

    // Update TCP Flags
    (tcp_flags & TH_FIN) ? flow->fin_flag_count++ : (void)0;
    (tcp_flags & TH_SYN) ? flow->syn_flag_count++ : (void)0;
    (tcp_flags & TH_RST) ? flow->rst_flag_count++ : (void)0;
    (tcp_flags & TH_PUSH) ? flow->psh_flag_count++ : (void)0;
    (tcp_flags & TH_ACK) ? flow->ack_flag_count++ : (void)0;
    (tcp_flags & TH_URG) ? flow->urg_flag_count++ : (void)0;
    (tcp_flags & 0x80) ? flow->cwr_flag_count++ : (void)0; // CWR Flag
    (tcp_flags & 0x40) ? flow->ece_flag_count++ : (void)0; // ECE Flag
  
    if(packet_direction == FWD){
        if(iat > 1000000){
            flow->total_fwd_subflows += 1;
        }

        flow->total_fwd_packets++;
        flow->total_fwd_bytes += len;
        flow->fwd_iat_total += iat;
        flow->fwd_header_len += header_length;
        flow->fwd_packets_per_sec = flow->total_fwd_packets / flow->flow_duration;
        flow->fwd_segment_size_tot += packet_size;
        (tcp_flags & TH_PUSH) ? flow->fwd_psh_flags++ : (void)0;
        (tcp_flags & TH_URG) ? flow->fwd_urg_flags++ : (void)0;
    
        // Update Min & Max Fwd packet len
        (len < flow->fwd_packet_len_min) ? flow->fwd_packet_len_min = len : (void)0;
        (len > flow->fwd_packet_len_max) ? flow->fwd_packet_len_max = len : (void)0;
    
        (iat < flow->fwd_iat_min) ? flow->fwd_iat_min = iat : (void)0;
        (iat > flow->fwd_iat_max) ? flow->fwd_iat_max = iat : (void)0;


        (packet_size < flow->fwd_seg_size_min) ? flow->fwd_seg_size_min = packet_size : (void)0;
        flow->fwd_segment_size_avg = flow->fwd_segment_size_tot / flow->total_fwd_packets;

        if(packet_size > 100){
            if(flow->last_fwd_packet_is_bulk == false){ // If prev wasnt bulk a new bulk transmission starts
                flow->num_fwd_bulk_transmissions++;
                flow->last_fwd_packet_is_bulk = true;
                flow->fwd_bulk_start = time(NULL);
                flow->fwd_bulk_end = time(NULL);
            }

          // Prev was a bulk so we just update end && aggregate features
            flow->fwd_bulk_end = time(NULL);
            flow->fwd_bytes_bulk_tot += packet_size;
            flow->fwd_bytes_curr_bulk += packet_size;
            flow->fwd_packet_bulk_tot++;
       
            flow->fwd_bytes_bulk_avg = flow->fwd_bytes_bulk_tot / flow->num_fwd_bulk_transmissions;
            flow->fwd_packet_bulk_avg = flow->fwd_packet_bulk_tot / flow->num_fwd_bulk_transmissions;
            flow->fwd_bulk_duration = flow->fwd_bulk_end - flow->fwd_bulk_start;

            if(flow->fwd_bulk_duration != 0){
                flow->fwd_bulk_rate_avg = (flow->fwd_bytes_bulk_tot / flow->fwd_bulk_duration) 
                                         / flow->num_fwd_bulk_transmissions;
            }
        } else { // Not a bulk packet
            flow->last_fwd_packet_is_bulk = false;
            flow->fwd_bytes_curr_bulk = 0; // Reset curr bulk to 0
        }
        if(flow->total_fwd_subflows > 0){
          flow->subflow_fwd_packets = flow->total_fwd_packets / flow->total_fwd_subflows;
          flow->subflow_fwd_bytes = flow->total_fwd_bytes / flow->total_fwd_subflows;
        }
    } // END IF PACKET DIRECTION FWD
    else { // Packet direction == BWD
        if(iat > 1000000){
            flow->total_bwd_subflows += 1;
        }

        flow->total_bwd_packets++;
        flow->total_bwd_bytes += len;
        flow->bwd_iat_total += iat;
        flow->bwd_header_len += header_length;
        flow->bwd_packets_per_sec = flow->total_bwd_packets / flow->flow_duration;
        flow->bwd_segment_size_tot += packet_size;

        (tcp_flags & TH_PUSH) ? flow->bwd_psh_flags++ : (void)0;
        (tcp_flags & TH_URG) ? flow->bwd_urg_flags++ : (void)0;

        (len < flow->bwd_packet_len_min) ? flow->bwd_packet_len_min = len : (void)0;
        (len > flow->bwd_packet_len_max) ? flow->bwd_packet_len_max = len : (void)0;

        (iat < flow->bwd_iat_min) ? flow->bwd_iat_min = iat : (void)0;
        (iat > flow->bwd_iat_max) ? flow->bwd_iat_max = iat : (void)0;

        flow->bwd_segment_size_avg = flow->bwd_segment_size_tot / flow->total_bwd_packets;

        if(packet_size > 100){
            if(flow->last_bwd_packet_is_bulk == false){
                flow->num_bwd_bulk_transmissions++;
                flow->last_bwd_packet_is_bulk = true;
                flow->bwd_bulk_start = time(NULL);
                flow->bwd_bulk_end = time(NULL);
            }

            flow->bwd_bulk_end = time(NULL);
            flow->bwd_bytes_bulk_tot += packet_size;
            flow->bwd_bytes_curr_bulk += packet_size;
            flow->bwd_packet_bulk_tot++;
       
            flow->bwd_bytes_bulk_avg = flow->bwd_bytes_bulk_tot / flow->num_bwd_bulk_transmissions;
            flow->bwd_packet_bulk_avg = flow->bwd_packet_bulk_tot / flow->num_bwd_bulk_transmissions;
            flow->bwd_bulk_duration = flow->bwd_bulk_end - flow->bwd_bulk_start;

            if(flow->bwd_bulk_duration != 0){
            flow->bwd_bulk_rate_avg = (flow->bwd_bytes_bulk_tot / flow->bwd_bulk_duration) 
                                       / flow->num_bwd_bulk_transmissions;
            }
        } 
        else {
            flow->last_bwd_packet_is_bulk = false;
            flow->bwd_bytes_curr_bulk = 0;
        }
        if(flow->total_fwd_subflows > 0){
            flow->subflow_fwd_packets = flow->total_fwd_packets / flow->total_fwd_subflows;
            flow->subflow_fwd_bytes = flow->total_fwd_bytes / flow->total_fwd_subflows;
        }

        (flow->bwd_init_win_bytes  != 0 && win_bytes != 0) ? flow->bwd_init_win_bytes = win_bytes : (void)0; 
    } // END IF PACKET DIRECTION == BWD

    // Overall statistics
    if(flow->total_bwd_bytes > 0){
        flow->down_up_ratio = flow->total_bwd_bytes / flow->total_fwd_bytes;
    } else {
        flow->down_up_ratio = 0;
    }

    flow->avg_packet_size = (flow->total_fwd_bytes + flow->total_bwd_bytes) / 
                            (flow->total_fwd_packets + flow->total_bwd_packets);
    
    
  
  /*
  new_entry->stats.fwd_act_data_packets = (packet_size > 1) ? 1 : 0;
  
  new_entry->stats.active_min = 0;
  new_entry->stats.active_mean = 0;
  new_entry->stats.active_max = 0;
  new_entry->stats.active_std = 0;

  new_entry->stats.idle_min = 0;
  new_entry->stats.idle_mean = 0;
  new_entry->stats.idle_max = 0;
  new_entry->stats.idle_std = 0;
  */
  pthread_mutex_unlock(&flow_mutex);
  return flow;
}


/* Extract TCP flags from packet data */
uint8_t get_tcp_flags(u_char* data, size_t len) {
    if(!data){
        fprintf(stderr, "ERROR (FFEXTR)[get_tcp_flags] NULL data ptr\n");
        return UINT8_MAX;
    }

    if (len < sizeof(struct ether_header)) {
        return 0;
    }

    const struct ether_header* eth_header = (const struct ether_header*)data;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return 0;
    }

    const uint8_t* ip_packet = data + sizeof(struct ether_header);
    size_t remaining_len = len - sizeof(struct ether_header);

    if (remaining_len < sizeof(struct ip)) {
        return 0;
    }

    const struct ip* ip_header = (const struct ip*)ip_packet;
    if (ip_header->ip_p != IPPROTO_TCP) {
        return 0;
    }

    uint32_t ip_header_len = ip_header->ip_hl * 4;
    remaining_len -= ip_header_len;

    if (remaining_len < sizeof(struct tcphdr)) {
        return 0;
    }

    const struct tcphdr* tcp_header = (const struct tcphdr*)(ip_packet + ip_header_len);
    
    uint8_t flags = 0;
    if (tcp_header->th_flags & TH_FIN) flags |= TH_FIN;
    if (tcp_header->th_flags & TH_SYN) flags |= TH_SYN;
    if (tcp_header->th_flags & TH_RST) flags |= TH_RST;
    if (tcp_header->th_flags & TH_PUSH) flags |= TH_PUSH;
    if (tcp_header->th_flags & TH_ACK) flags |= TH_ACK;
    if (tcp_header->th_flags & TH_URG) flags |= TH_URG;
    // ARREGLAR ESTO
    #ifdef TH_CWR
        if (tcp_header->th_flags & TH_CWR) flags |= TH_CWR;
    #endif
    #ifdef TH_ECE
        if (tcp_header->th_flags & TH_ECE) flags |= TH_ECE;
    #endif

    return flags;
}

uint32_t get_header_len(uint8_t* data, size_t len) {
    if(!data){
      fprintf(stderr, "ERROR (FFEXTR)[get_packet_direction]: NULL Pointer received\n");
      return UINT32_MAX;
    }

    if (len < sizeof(struct ether_header)) {
        return 0;
    }

    uint32_t header_len = sizeof(struct ether_header); // Start with ethernet header

    const struct ether_header* eth_header = (const struct ether_header*)data;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return header_len;
    }

    const uint8_t* ip_packet = data + sizeof(struct ether_header);
    size_t remaining_len = len - sizeof(struct ether_header);

    if (remaining_len < sizeof(struct ip)) {
        return header_len;
    }

    const struct ip* ip_header = (const struct ip*)ip_packet;
    uint32_t ip_header_len = ip_header->ip_hl * 4;
    header_len += ip_header_len;

    if (ip_header->ip_p == IPPROTO_TCP) {
        remaining_len -= ip_header_len;
        if (remaining_len >= sizeof(struct tcphdr)) {
            const struct tcphdr* tcp_header = (const struct tcphdr*)(ip_packet + ip_header_len);
            header_len += tcp_header->th_off * 4; // TCP header length
        }
  } 

    return header_len;
}

uint32_t get_tcp_window_size(u_char* data, size_t len) {
    if(!data){
      fprintf(stderr, "ERROR (FFEXTR)[get_packet_direction]: NULL Pointer received\n");
      return UINT32_MAX;
    }

    if (len < sizeof(struct ether_header)) {
        return 0;
    }

    const struct ether_header* eth_header = (const struct ether_header*)data;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return 0;
    }

    const uint8_t* ip_packet = data + sizeof(struct ether_header);
    size_t remaining_len = len - sizeof(struct ether_header);

    if (remaining_len < sizeof(struct ip)) {
        return 0;
    }

    const struct ip* ip_header = (const struct ip*)ip_packet;
    if (ip_header->ip_p != IPPROTO_TCP) {
        return 0;
    }

    uint32_t ip_header_len = ip_header->ip_hl * 4;
    remaining_len -= ip_header_len;

    if (remaining_len < sizeof(struct tcphdr)) {
        return 0;
    }

    const struct tcphdr* tcp_header = (const struct tcphdr*)(ip_packet + ip_header_len);
    
    // Extract the window size field and convert from network to host byte order
    uint16_t window_size = ntohs(tcp_header->th_win);
    
    return window_size;
}


flow_direction_t get_packet_direction(flow_stats_t* flow, flow_key_t* key){
  if(!flow || !key){
    fprintf(stderr, "ERROR (FFEXTR)[get_packet_direction]: NULL Pointer received\n");
    return FWD;
  }

  printf("DEBUG [get_packet_direction] %u\n", flow->dst_ip_fwd);
  printf("DEBUG [get_packet_direction] %u\n", key->dst_ip);
  if(flow->dst_ip_fwd == key->dst_ip){
    return FWD;
  } else{
    return BWD;
  }
}
