#include <pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <math.h>

#include "nids_backend.h"
#include "flow_feature_extractor.h"


static volatile bool ffextr_running = false;

int packets_processed;
int flow_count;
int active_flows;

pthread_t flow_manager_thread;

struct flow_entry** flow_table = NULL;
int flow_hashmap_size;
pthread_mutex_t flow_mutex = PTHREAD_MUTEX_INITIALIZER;

void* flow_manager_thread_func();
void update_flow_time_features(flow_stats_t* flow, time_t ts); 
inline void update_mean_std(uint64_t *count, double *mean, double *M2, double new_value);
static void update_flags(flow_stats_t *flow, uint8_t tcp_flags);
static void init_service_flag(flow_stats_t *stats); 
static bool flow_keys_match(flow_key_t *key, flow_key_t *key2);

// Helper macros
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define UPDATE_MIN(var, val) ((val) < (var) ? (var) = (val) : (void)0)
#define UPDATE_MAX(var, val) ((val) > (var) ? (var) = (val) : (void)0)

// Helper functions
static double mean(uint64_t sum, size_t count){
    return count == 0 ? 0 : (double)sum/count;
}

int init_feature_extractor(){
    flow_count = 0;
    active_flows = 0;
    flow_hashmap_size = config->flow_table_init_size;

    flow_table = calloc(flow_hashmap_size, sizeof(flow_entry_t*));
    if(!flow_table){
        log_error("Failed to allocate the flow table");
        return NIDS_ERROR;
    }
    return NIDS_OK; 
  }



/* Lanzadera del hilo y asignacion de su funcion flow_manager_thread_func */ 
int start_flow_manager(void){
    if(ffextr_running){
        log_warn("Flow manager is already running");
        return NIDS_ERROR;
    }

    if(pthread_create(&flow_manager_thread, NULL, flow_manager_thread_func, NULL) != 0){
        log_error("Flow manager thread could not be created succesfully");
        ffextr_running = false;
        return NIDS_ERROR;
    }
    ffextr_running = true;
    return NIDS_OK;
}



void* flow_manager_thread_func(){
    packet_info_t packet;

    log_debug("Inside flow manager function");

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setname_np(pthread_self(), "flow_manager");
    
    time_t last_update_time = time(NULL);

    while(ffextr_running){
        if(dequeue_packet(&packet) >= 0){
            process_packet(packet.data, packet.len, packet.time_microseconds);
            free(packet.data);
        }
        
        time_t curr_time = time(NULL);
        time_t update_time = curr_time - last_update_time;
        
        // Each second I check whether there are flows to be 
        if(update_time >= 1){
            update_all_flows();
            last_update_time = curr_time;
        }
    }
    return NULL;
  }



void process_packet(uint8_t* data, size_t len, uint64_t time_microseconds){
    if(!data){
        log_warn("NULL data ptr received in process packet");
        return;
    }

    flow_key_t* key = get_flow_key(data, len);
    if(!key){
        log_warn("Flow key couldnt be computed");
        return;
    }

    u_int32_t flow_hash = hash_key(key);
    if(flow_hash == UINT32_MAX){
        log_warn("Flow hash couldnt be computed properly");
        return;
    }

    flow_stats_t* existing_flow = get_flow(key, flow_hash);
    if(!existing_flow){
        flow_stats_t* created = create_flow(key, flow_hash, data, len, time_microseconds);
        if(!created){
            log_warn("Flow couldnt be created in hashmap");
            return;
        }
        log_debug("Flow %u created", flow_hash);
    
    } else {
        flow_stats_t* updated = update_flow(key, existing_flow, data, len, time_microseconds);
        if(!updated){
            log_warn("Flow couldnt be updated");
            return;
        } else {
            log_info("Flow was updated successfully");
          }
      }
    free(key);
    packets_processed++;
    if((packets_processed % 1000) == 0){
        log_debug("Packets processed %d", packets_processed);
    } 
  }



/* Returns a flow_key_t with processed_packet data */
flow_key_t* get_flow_key(const u_char* pkt_data, size_t len){
    if(!pkt_data){
        log_error("Null pkt_data pointer");
        return NULL;
    }
 
    if(len < sizeof(struct ether_header)){
        log_warn("Packet too short for Ethernet header");
        return NULL;
    }

    struct ether_header* eth_header = (struct ether_header*)pkt_data;
    log_debug("Ethernet header size: %zu bytes", sizeof(struct ether_header));
    log_debug("Ethernet type: 0x%04x\n", ntohs(eth_header->ether_type));

    if(ntohs(eth_header->ether_type) != ETHERTYPE_IP){
        log_warn("Not an IP packet, can't get the flow_key, discarding packet");
        return NULL;
    }

    const u_char* ip_packet = pkt_data + sizeof(struct ether_header);
    size_t remaining_len = len - sizeof(struct ether_header);

    if(remaining_len < sizeof(struct ip)){
        log_warn("Packet too short for IP headr, discarding packet");
        return NULL;
    }

    struct ip* ip_header = (struct ip*)ip_packet; 
    unsigned int ip_header_len = ip_header->ip_hl * 4;
  
    if(ip_header->ip_v != 4){
        log_warn("Not an IPV4 packet, discarding packet");
        return NULL;
    }

    // printf("(FFEXTR)[get_flow_key] IP version: %u\n", ip_header->ip_v);
    log_debug("IP header length: %u bytes\n", ip_header_len);
    log_debug("IP total length: %u bytes\n", ntohs(ip_header->ip_len));
    // printf("(FFEXTR)[get_flow_key] IP protocol: %u\n", ip_header->ip_p);

    if(ip_header_len < 20 || remaining_len < ip_header_len){
        log_warn("Invalid IP header length, discarding packet");
        return NULL;
    }
    
    // Now we're ready to allocate memory, before we were discarding the packet so bullshit
    flow_key_t* flow_key = calloc(1, sizeof(flow_key_t));

    if(!flow_key){
        log_error("Failed to allocate memory for the flow_key struct");
        return NULL;
    }
    flow_key->src_ip = ntohl(ip_header->ip_src.s_addr);
    flow_key->dst_ip = ntohl(ip_header->ip_dst.s_addr);
    flow_key->protocol = ip_header->ip_p;


    if(flow_key->protocol == IPPROTO_TCP){
        const u_char* tcp_packet = ip_packet + ip_header_len;
        remaining_len -= ip_header_len;

        if(remaining_len < sizeof(struct tcphdr)){
            log_warn("Packet too short for TCP header, discarding packet");
            free(flow_key);
            return NULL;
        }

        const struct tcphdr* tcp_header = (struct tcphdr*) tcp_packet;
        flow_key->src_port = ntohs(tcp_header->source);
        flow_key->dst_port = ntohs(tcp_header->dest);
    }
    // printf("DEBUG (FFEXTR)[get_flow_key] PROTOCOL: %u \n", flow_key->protocol);
    log_debug("Flow key: %s:%u -> %s:%u (proto %u)", inet_ntoa(ip_header->ip_src), flow_key->src_port,
                inet_ntoa(ip_header->ip_dst), flow_key->dst_port, flow_key->protocol);

    return flow_key;
  }



void stop_flow_manager(void){
    if(!ffextr_running){
        log_warn("Flow manager was already running");
        return;
    }

    ffextr_running = false;
    shutdown_packet_queue(); 
    pthread_join(flow_manager_thread, NULL); // Now thread will not queue and dequeue packets
    
    // So we're ready to free
    if(flow_table){
        cleanup_flow_table();
        free(flow_table);
        flow_table = NULL;
    }
    log_info("Stopped the flow_manager_thread");
  }



// Simple hashing function 
uint32_t hash_key(flow_key_t* key) {
    if(!key){
        log_error("Null key pointer received");
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
        log_error("Null key or data ptr received in create flow");
        return NULL;
    }
    pthread_mutex_lock(&flow_mutex);
  
    flow_entry_t* new_entry = (flow_entry_t*)malloc(sizeof(flow_entry_t));
    if(new_entry == NULL){
        log_error("Failed to allocate memory for new flow entry");
        pthread_mutex_unlock(&flow_mutex);
        return NULL;
    }
  
    memset(&new_entry->stats, 0, sizeof(flow_stats_t));
    memcpy(&new_entry->stats.key, key, sizeof(flow_key_t));

    init_service_flag(&new_entry->stats);
 
    new_entry->stats.status = FLOW_STATUS_ACTIVE;
    new_entry->stats.close_state = CLOSE_STATE_OTHER;
    new_entry->stats.active_counts++;

    new_entry->stats.flow_start_time = time_microseconds;
    new_entry->stats.flow_last_time = time_microseconds;
    new_entry->stats.last_checked_time = time_microseconds;
 
    new_entry->stats.flow_hash = flow_hash;

    //printf("DEBUG (FFEXTR)[create_flow] Fow_start_time : %ld\n", new_entry->stats.flow_start_time);
 
    new_entry->stats.total_packets = 1;
    new_entry->stats.total_bytes = len;
    new_entry->stats.total_fwd_packets = 1; 
    new_entry->stats.total_fwd_bytes = len;

    new_entry->stats.fwd_packet_len_min = len;
    new_entry->stats.fwd_packet_len_max = len;
    new_entry->stats.fwd_packet_len_mean = len;
    new_entry->stats.fwd_packet_len_std = len;
    new_entry->stats.bwd_packet_len_min = UINT16_MAX;

    new_entry->stats.flow_bytes_per_sec = len;
    new_entry->stats.flow_packets_per_sec = 1;
    new_entry->stats.fwd_packets_per_sec = 1;

    new_entry->stats.flow_iat_min = UINT64_MAX;
    new_entry->stats.fwd_iat_min = UINT64_MAX;
    new_entry->stats.bwd_iat_min = UINT64_MAX;

    uint8_t tcp_flags = get_tcp_flags(data, len);
    update_flags(&new_entry->stats, tcp_flags);
    new_entry->stats.fwd_psh_flags = (tcp_flags & TH_PUSH) ? 1 : 0;
    new_entry->stats.fwd_urg_flags = (tcp_flags & TH_URG) ? 1 : 0;

    uint32_t header_length = get_header_len(data, len);
    new_entry->stats.fwd_header_len = header_length;

    new_entry->stats.packet_len_min = len;
    new_entry->stats.packet_len_max = len;
    new_entry->stats.packet_len_mean = len;
 
    new_entry->stats.avg_packet_size = len;
    size_t packet_size = len - header_length;
    new_entry->stats.fwd_segment_size_avg = packet_size; // Tamaño segmento = paquete - cabeceras
    new_entry->stats.fwd_segment_size_tot = packet_size;
    new_entry->stats.fwd_seg_size_min = packet_size;

    if(packet_size >= BULK_THRESHOLD){
        new_entry->stats.count_possible_fwd_bulk_packets = 1;
    }

    uint32_t init_win_bytes = get_tcp_window_size(data,len);
    new_entry->stats.fwd_init_win_bytes = init_win_bytes;
    new_entry->stats.fwd_act_data_packets = (packet_size > 1) ? 1 : 0;

    // Apunto al anterior flujo que tenia ese hash
    new_entry->next = flow_table[flow_hash];
    // Ahora la key del hashmap es el nuevo flujo que encabeza la linked_list
    flow_table[flow_hash] = new_entry;
  
    flow_count++;
    active_flows++;
    log_debug("Created new flow, active flow count: %d", flow_count);

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
        if(flow_keys_match(&current_flow->stats.key, key)){
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
    // If packet arrived so late that flow should be considereded expired
    if(iat >= EXPIRE_THRESHOLD){
        flow->status = FLOW_STATUS_EXPIRED;
        pthread_mutex_unlock(&flow_mutex);
        return flow;
    } else if(flow->status == FLOW_STATUS_CLOSED || flow->status == FLOW_STATUS_EXPIRED){ // If flow its closed or expired
        pthread_mutex_unlock(&flow_mutex);
        return flow; // Same
    } else {
        flow->curr_idle_time_tot = 0; // Flow ain't expired or closed -> Reset idle time
    } 


    flow_direction_t packet_direction = get_packet_direction(flow, key);
    // printf("Flow direction of packet %d\n", packet_direction);
    uint8_t tcp_flags = get_tcp_flags(data, len);
    uint32_t header_length = get_header_len(data, len);
    size_t packet_size = len - header_length;
    uint32_t win_bytes = get_tcp_window_size(data,len);
   
    
    /* GLOBAL PACKET FEATURES: TIME FEATURES */
    uint64_t cum_time = time_microseconds - flow->last_checked_time; 
    flow->last_checked_time = time_microseconds;
    flow->flow_last_time = time_microseconds;

    if(flow->status == FLOW_STATUS_ACTIVE){
        if(iat < ACTIVITY_TIMEOUT){
            update_mean_std(&flow->active_counts, &flow->active_mean, &flow->active_time_M2, cum_time);
            flow->active_time_tot += cum_time;
            flow->curr_active_time_tot += cum_time;
            (flow->curr_active_time_tot < flow->active_min) ? flow->active_min = flow->curr_active_time_tot : (void)0;
            (flow->curr_active_time_tot > flow->active_max) ? flow->active_max = flow->curr_active_time_tot : (void)0;
        } else { // If I was active but iat is so big it should be considered idle time. Flow is still active, but this is idle time
            flow-> idle_time_tot += cum_time;
            flow-> idle_time_tot += cum_time;
            (flow->curr_idle_time_tot < flow->idle_min) ? flow->idle_min = flow->curr_idle_time_tot : (void)0;
            (flow->curr_idle_time_tot > flow->idle_max) ? flow->idle_max = flow->curr_idle_time_tot : (void)0;
        }
    } else { // Flow is IDLE
        update_mean_std(&flow->idle_counts, &flow->idle_mean, &flow->idle_time_M2, cum_time);
        flow->idle_time_tot += cum_time;
        flow->curr_idle_time_tot += cum_time;
        (flow->curr_idle_time_tot < flow->idle_min) ? flow->idle_min = flow->curr_idle_time_tot : (void)0;
        (flow->curr_idle_time_tot > flow->idle_max) ? flow->idle_max = flow->curr_idle_time_tot : (void)0;
        flow->curr_active_time_tot = 0;
        flow->status = FLOW_STATUS_ACTIVE;
        flow->active_counts++;
    } 
     
    flow->total_packets++;
    flow->total_bytes += len;

    // Update flow IAT
    flow->flow_iat_total += iat;
    (iat > flow->flow_iat_max) ? flow->flow_iat_max = iat : (void)0;
    (iat < flow->flow_iat_min) ? flow->flow_iat_min = iat : (void)0;

    // Update packet len Min & Max
    (flow->packet_len_min < len) ? flow->packet_len_min = len : (void)0;
    (flow->packet_len_max < len) ? flow->packet_len_max = len : (void)0;

    // Update TCP Flags
    update_flags(flow, tcp_flags); 
    
    update_mean_std(&flow->total_packets , &flow->flow_iat_mean, &flow->flow_iat_M2, len);
    update_mean_std(&flow->total_packets, &flow->packet_len_mean, &flow->packet_len_M2, len);

    /* FWD AND BACKWARD FLOW FEATURES */
    if(packet_direction == FWD){
        // CLOSING HANDSHAKE STATUS
        if((tcp_flags & TH_FIN)){ // FIN CLI
            flow->close_state = CLOSE_STATE_FIN_CLI;
        }
        
        if((tcp_flags & TH_ACK) && flow->close_state == CLOSE_STATE_ACK_FIN_SV){ // ACK CLI
            flow->close_state = CLOSE_STATE_ACK_CLI;
            flow->status = FLOW_STATUS_CLOSED;
        }
        
        // NEW SUBFLOW
        (iat >= SUBFLOW_THRESHOLD) ? flow->total_fwd_subflows++ : (void)0;
      
        flow->total_fwd_packets++;
        flow->total_fwd_bytes += len;
        flow->fwd_iat_total += iat;
        flow->fwd_header_len += header_length;
        flow->fwd_segment_size_tot += packet_size;
        (tcp_flags & TH_PUSH) ? flow->fwd_psh_flags++ : (void)0;
        (tcp_flags & TH_URG) ? flow->fwd_urg_flags++ : (void)0;
    
        // Update Min & Max Fwd packet len
        (len < flow->fwd_packet_len_min) ? flow->fwd_packet_len_min = len : (void)0;
        (len > flow->fwd_packet_len_max) ? flow->fwd_packet_len_max = len : (void)0;
    
        (iat < flow->fwd_iat_min) ? flow->fwd_iat_min = iat : (void)0;
        (iat > flow->fwd_iat_max) ? flow->fwd_iat_max = iat : (void)0;
        

        (packet_size < flow->fwd_seg_size_min) ? flow->fwd_seg_size_min = packet_size : (void)0;
        update_mean_std(&flow->total_fwd_packets, &flow->fwd_packet_len_mean, &flow->fwd_packet_len_M2,len);
        update_mean_std(&flow->total_fwd_packets, &flow->fwd_iat_mean, &flow->fwd_iat_M2, len);

        /* FWD BULK FEATURES */
        if(packet_size >= BULK_THRESHOLD){
            flow->count_possible_fwd_bulk_packets++;
            if(flow->count_possible_fwd_bulk_packets >= 4){
                if(flow->in_fwd_bulk_transmission == false){ // BULK START WITH THIS PACKET
                    flow->in_fwd_bulk_transmission = true;
                    flow->num_fwd_bulk_transmissions++;
                    flow->fwd_bulk_start = time_microseconds;
                    flow->fwd_bulk_end = time_microseconds;
                }

                // BULK ACTIVE ALRDY
                flow->fwd_bulk_end = time_microseconds;
                flow->fwd_bytes_bulk_tot += len;
                flow->fwd_bytes_curr_bulk += len;
                flow->fwd_packet_bulk_tot++;
                
                }
            }
        else { // NOT A FWD BULK PACKET
            if(flow->in_fwd_bulk_transmission){
                flow->fwd_bulk_duration += (flow->fwd_bulk_end - flow->fwd_bulk_start);
            }
            flow->in_fwd_bulk_transmission = false;
            flow->count_possible_fwd_bulk_packets = 0;
            flow->fwd_bytes_curr_bulk = 0; // Reset curr bulk to 0
        }
    } // END IF PACKET DIRECTION FWD

    else { // Packet direction == BWD
        (flow->bwd_init_win_bytes  != 0 && win_bytes != 0) ? flow->bwd_init_win_bytes = win_bytes : (void)0; // Set up win bytes in bwd dir 
        // TCP CLOSING HANDSHAKE STATUS 
        if((tcp_flags & TH_ACK) && (tcp_flags & TH_FIN) && flow->close_state == CLOSE_STATE_FIN_CLI){
            flow->close_state = CLOSE_STATE_ACK_FIN_SV;
        }

        (iat > SUBFLOW_THRESHOLD) ? flow->total_bwd_subflows++ : (void)0;
        flow->total_bwd_packets++;
        flow->total_bwd_bytes += len;
        flow->bwd_iat_total += iat;
        flow->bwd_header_len += header_length;
        //flow->bwd_packets_per_sec = flow->total_bwd_packets / flow->flow_duration;
        flow->bwd_segment_size_tot += packet_size;
        (tcp_flags & TH_PUSH) ? flow->bwd_psh_flags++ : (void)0;
        (tcp_flags & TH_URG) ? flow->bwd_urg_flags++ : (void)0;

        // MIN & MAX VALUES
        (len < flow->bwd_packet_len_min) ? flow->bwd_packet_len_min = len : (void)0;
        (len > flow->bwd_packet_len_max) ? flow->bwd_packet_len_max = len : (void)0;

        (iat < flow->bwd_iat_min) ? flow->bwd_iat_min = iat : (void)0;
        (iat > flow->bwd_iat_max) ? flow->bwd_iat_max = iat : (void)0;
         
        update_mean_std(&flow->total_bwd_packets, &flow->bwd_packet_len_mean, &flow->bwd_packet_len_M2,len);
        update_mean_std(&flow->total_bwd_packets, &flow->bwd_iat_mean, &flow->bwd_iat_M2, len);

        if(packet_size > BULK_THRESHOLD){
            flow->count_possible_bwd_bulk_packets++;
            if(flow->count_possible_bwd_bulk_packets >= 3){
                if(flow->in_bwd_bulk_transmission == false){
                    flow->in_bwd_bulk_transmission = true;
                    flow->num_bwd_bulk_transmissions++;
                    flow->bwd_bulk_start = time_microseconds;
                    flow->bwd_bulk_end = time_microseconds;
                }

            // BULK ACTIVE ALRDY
            flow->bwd_bulk_end = time_microseconds;
            flow->bwd_bytes_bulk_tot += len;
            flow->bwd_bytes_curr_bulk += len;
            flow->bwd_packet_bulk_tot++;
            
            }
        } 
        else { // NOT A BWD BULK PACKET
            if(flow->in_bwd_bulk_transmission){
                flow->bwd_bulk_duration += (flow->bwd_bulk_end - flow->bwd_bulk_start);
            }
            flow->in_bwd_bulk_transmission = false;
            flow->count_possible_bwd_bulk_packets = 0;
            flow->bwd_bytes_curr_bulk = 0; // Reset curr bulk to 0
        }
    } // END IF PACKET DIRECTION BWD  
    pthread_mutex_unlock(&flow_mutex);
    return flow; 
}

void compute_cumulative_features(flow_stats_t* flow){
    if(!flow){
        fprintf(stderr, "ERROR [ffextr](updt_flow_t_ftrs) Invalid flow pointer\n");
    }
    
    flow->flow_duration = flow->flow_last_time - flow->flow_start_time;
    
    flow->fwd_packet_len_mean = mean(flow->total_fwd_bytes, flow->total_fwd_packets);
    flow->bwd_packet_len_mean = mean(flow->total_bwd_bytes, flow->total_bwd_packets);
    flow->flow_bytes_per_sec = mean((flow->total_fwd_bytes + flow->total_bwd_bytes), flow->flow_duration);
    flow->flow_packets_per_sec = mean((flow->total_fwd_packets + flow->total_bwd_packets), flow->flow_duration);
    flow->flow_iat_mean = mean(flow->flow_iat_total, flow->flow_duration);
    flow->fwd_iat_mean = mean(flow->fwd_iat_total, flow->flow_duration);
    flow->bwd_iat_mean = mean(flow->bwd_iat_total, flow->flow_duration);
    flow->fwd_packets_per_sec = mean(flow->total_fwd_packets, flow->flow_duration);
    flow->bwd_packets_per_sec = mean(flow->total_bwd_packets, flow->flow_duration);
    flow->packet_len_mean = mean((flow->total_fwd_bytes + flow->total_bwd_bytes), (flow->total_fwd_packets + flow->total_bwd_packets));
    flow->down_up_ratio = mean(flow->total_bwd_bytes, flow->total_fwd_bytes);
    flow->avg_packet_size = mean((flow->fwd_segment_size_tot + flow->bwd_segment_size_tot), (flow->total_fwd_packets + flow->total_bwd_packets));
    flow->fwd_segment_size_avg = mean(flow->fwd_segment_size_tot, flow->total_fwd_packets);
    flow->bwd_segment_size_avg = mean(flow->bwd_segment_size_tot, flow->total_bwd_packets);
     
    double fwd_bulk_avg = mean(flow->fwd_bytes_bulk_tot, flow->fwd_bulk_duration);
    flow->fwd_bulk_rate_avg = mean(fwd_bulk_avg, flow->num_fwd_bulk_transmissions);
    flow->fwd_packet_bulk_avg = mean(flow->fwd_bytes_bulk_tot, flow->num_fwd_bulk_transmissions);
    flow->fwd_bytes_bulk_avg = mean(flow->fwd_bytes_bulk_tot, flow->num_fwd_bulk_transmissions);
 
    double bwd_bulk_avg = mean(flow->bwd_bytes_bulk_tot, flow->bwd_bulk_duration);
    flow->bwd_bulk_rate_avg = mean(bwd_bulk_avg, flow->num_bwd_bulk_transmissions);
    flow->bwd_packet_bulk_avg = mean(flow->bwd_bytes_bulk_tot, flow->num_bwd_bulk_transmissions);
    flow->bwd_bytes_bulk_avg = mean(flow->bwd_bytes_bulk_tot, flow->num_bwd_bulk_transmissions);

    flow->subflow_fwd_packets = mean(flow->total_fwd_packets, flow->total_fwd_subflows);
    flow->subflow_fwd_bytes = mean(flow->total_fwd_bytes, flow->total_fwd_subflows);
    flow->active_mean = mean(flow->active_time_tot, flow->active_counts);
    flow->idle_mean = mean(flow->idle_time_tot, flow->idle_counts);

    flow->fwd_packet_len_std = compute_std(flow->fwd_packet_len_M2, flow->total_fwd_packets);
    flow->bwd_packet_len_std = compute_std(flow->bwd_packet_len_M2, flow->total_bwd_packets);
    flow->packet_len_std = compute_std(flow->packet_len_M2, flow->total_packets);
    
    // For IAT values, we need at least 3 packets to have 2 intervals
    flow->flow_iat_std = (flow->total_packets > 2) ? 
        compute_std(flow->flow_iat_M2, flow->total_packets - 1) : 0.0;
    
    flow->fwd_iat_std = (flow->total_fwd_packets > 2) ? 
        compute_std(flow->fwd_iat_M2, flow->total_fwd_packets - 1) : 0.0;
    
    flow->bwd_iat_std = (flow->total_bwd_packets > 2) ? 
        compute_std(flow->bwd_iat_M2, flow->total_bwd_packets - 1) : 0.0;
    
    flow->active_std = compute_std(flow->active_time_M2, flow->active_counts);
    flow->idle_std = compute_std(flow->idle_time_M2, flow->idle_counts);
}


static bool flow_keys_match(flow_key_t *a, flow_key_t *b){
    return a->protocol == b->protocol && (
           /* same direction */      (a->src_ip   == b->src_ip   &&
                                      a->dst_ip   == b->dst_ip   &&
                                      a->src_port == b->src_port &&
                                      a->dst_port == b->dst_port) ||

           /* reverse direction */   (a->src_ip   == b->dst_ip   &&
                                      a->dst_ip   == b->src_ip   &&
                                      a->src_port == b->dst_port &&
                                      a->dst_port == b->src_port));
}



void update_flow_time_features(flow_stats_t *flow, time_t ts){
    if((ts - flow->flow_last_time) >= EXPIRE_THRESHOLD){
        flow->status = FLOW_STATUS_EXPIRED;
    }
    if((ts - flow->flow_last_time) >= ACTIVITY_TIMEOUT && flow->status == FLOW_STATUS_ACTIVE){

        flow->status = FLOW_STATUS_IDLE;
        flow->idle_counts++;
        flow->curr_active_time_tot = 0;
    }
    if(flow->status == FLOW_STATUS_ACTIVE){
        flow->active_time_tot += ts - flow->last_checked_time;
        flow->curr_active_time_tot += ts - flow->last_checked_time;
    } else if(flow->status == FLOW_STATUS_IDLE){
        flow->idle_time_tot += ts - flow->last_checked_time;
        flow->curr_idle_time_tot += ts - flow->last_checked_time;
    }
    flow->last_checked_time = ts;
}

bool update_all_flows(){
    pthread_mutex_lock(&flow_mutex);
    uint64_t current_time = time(NULL) * 1000000;
    // Only the flows which are expired  || closed will be classified
    for(int i = 0; i < flow_hashmap_size; i++){
        flow_entry_t* current = flow_table[i]; 
        flow_entry_t* prev = NULL;
        while(current != NULL){
            
            if(current->stats.status == FLOW_STATUS_EXPIRED || current->stats.status == FLOW_STATUS_CLOSED){ // Flow its closed ready to classify
                compute_cumulative_features(&current->stats);
                int prediction = classify_flow(&current->stats);
                remove_flow(&current, &prev, i);
                
                continue;
            } else{
                // Check if flow is expired, idle and update time features
                update_flow_time_features(&current->stats, current_time);
                prev = current;
            }
            current = current->next;
        }
    }
    pthread_mutex_unlock(&flow_mutex);
    return true;
}


bool remove_flow(flow_entry_t** curr, flow_entry_t** prev, int hash_index){
    if (!curr || !*curr) {
        fprintf(stderr, "ERROR (FFEXTR)[remove_flow]: NULL flow entry pointer\n");
        return false;
    }

    flow_entry_t* to_remove = *curr;

    if(*prev == NULL){
        flow_table[hash_index] = to_remove->next;
    } else{
        (*prev)->next = to_remove->next;
    }
    
    *curr = to_remove->next;
    free(to_remove);
    active_flows--;
    return true;
}

int cleanup_flow_table(){
    pthread_mutex_lock(&flow_mutex);

    if(!flow_table){
        log_error("Flow table already cleaned");
        pthread_mutex_unlock(&flow_mutex);
        return NIDS_ERROR;
    }

    for(int i = 0; i < flow_hashmap_size; i++){
        flow_entry_t *current = flow_table[i];
        while(current != NULL){
            flow_entry_t *next = current->next;
            free(current);
            current = next;
      }
      flow_table[i] = NULL;
    }
    active_flows = 0;
    flow_count = 0;
    pthread_mutex_unlock(&flow_mutex);
    return NIDS_OK;
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


static void update_flags(flow_stats_t *flow, uint8_t tcp_flags){
    if (tcp_flags & TH_FIN) flow->fin_flag_count++;
    if (tcp_flags & TH_SYN) flow->syn_flag_count++;
    if (tcp_flags & TH_RST) flow->rst_flag_count++;
    if (tcp_flags & TH_PUSH) flow->psh_flag_count++;
    if (tcp_flags & TH_ACK) flow->ack_flag_count++;
    if (tcp_flags & TH_URG) flow->urg_flag_count++;
    if (tcp_flags & CWR_FLAG) flow->cwr_flag_count++;
    if (tcp_flags & ECE_FLAG) flow->ece_flag_count++;
}


static void init_service_flag(flow_stats_t* stats) {
    uint16_t dst_port = stats->key.dst_port;
    
    // Reset all service flags
    stats->serv_ssh = false;
    stats->serv_telnet = false;
    stats->serv_http = false;
    stats->serv_https = false;
    stats->serv_rtsp = false;
    stats->serv_mqtt = false;
    stats->serv_http_alt = false;
    stats->serv_remote_shell = false;
    stats->serv_custom_service = false;
    stats->serv_irc = false;
    stats->serv_unknown_app = false;
    stats->serv_iot_gateway = false;
    stats->serv_other = false;
    stats->serv_ephimeral = false;
    stats->serv_common_iot = false; 
    // Check specific services
    switch (dst_port) {
        case 22:    // SSH
            stats->serv_ssh = true;
            break;
        case 23:    // Telnet
            stats->serv_telnet = true;
            break;
        case 80:    // HTTP
        case 81:    // HTTP
        case 8000:  // HTTP
            stats->serv_http = true;
            break;
        case 443:   // HTTPS
            stats->serv_https = true;
            break;
        case 554:   // RTSP
            stats->serv_rtsp = true;
            break;
        case 1883:  // MQTT
            stats->serv_mqtt = true;
            break;
        case 8080:  // HTTP-Alt
            stats->serv_http_alt = true;
            break;
        case 4321:  // RemoteShell/CustomApp
            stats->serv_remote_shell = true;
            break;
        case 3333:  // CustomService/IRC-Alt
            stats->serv_custom_service = true;
            break;
        case 6668:  // IRC
            stats->serv_irc = true;
            break;
        case 9197:  // UnknownApp
            stats->serv_unknown_app = true;
            break;
        case 10002: // IoT-Gateway
            stats->serv_iot_gateway = true;
            break;
        default:
        if (dst_port >= 8000 && dst_port <= 9000) {
            stats->serv_common_iot = true;
        } else if (dst_port >= 49152 && dst_port <= 65535) {
            stats->serv_ephimeral = true;
        } else {
            stats->serv_other = true;
        }
        break;
    }
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

  log_debug("Packet direction %u\n", key->dst_ip);
  if(flow->key.src_ip == key->src_ip && 
       flow->key.src_port == key->src_port &&
       flow->key.dst_ip == key->dst_ip && 
       flow->key.dst_port == key->dst_port) {
        return FWD;
    } else {
        return BWD;
    }
}

/* UPDATE MEAN AND STD USING WELLFORD'S ONLINE ALGORITHM */ 
inline void update_mean_std(uint64_t *count, double *mean, double *M2, double new_value){
    (*count)++;
    
    double delta = new_value - *mean;
    *mean += delta / (*count);

    double delta2 = new_value - *mean;
    *M2 += delta * delta2;
}

double compute_std(double M2, size_t count) {
    if (count <= 1) {
        return 0.0;  // Need at least 2 values for sample standard deviation
    }
    
    // Use count-1 for sample standard deviation (Bessel's correction)
    return sqrt(M2 / (count - 1));
}

int get_flow_count(void){
    return flow_count; 
}

int get_packets_processed(void){
    return packets_processed;
}
