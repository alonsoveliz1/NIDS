#ifndef NIDS_BACKEND_H
#define NIDS_BACKEND_H

#include <stdbool.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

typedef struct{
  char* interface_name;
  int bufsize;
  int flow_table_init_size;
  char* model_path;
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

typedef enum{
    ACTIVE = 1,
    IDLE = 2,
    CLOSED = 3,
    EXPIRED = 4
} flow_status_t;

typedef enum{
  OTHER = 0,
  FIN_CLI = 1,
  ACK_FIN_SV,
  ACK_CLI
} flow_close_state_t;


/* Here will go all the features my model needs to class¡fy */
typedef struct{
    flow_key_t key;

    bool expired;
    flow_status_t status;            // Flow [active, idle, closed, expired]
    uint64_t last_checked_time;      // Last time that the flow was updated or received a packet 
    flow_close_state_t close_state; 
    //

    uint32_t dst_ip_fwd;             // Feature to check if flow is fwd or bwd
    uint32_t flow_hash;              // Hash of the flow key
    //

    // Flow duration
    uint64_t flow_start_time;        // Start timestamp of the flow
    uint64_t flow_last_time;         // Last seen timestamp (last packet seen in flow)
    uint64_t flow_duration;          // Duration of the flow in microseconds
    //

    // Packet counts
    uint32_t total_fwd_packets;      // Total packets in forward direction
    uint32_t total_bwd_packets;      // Total packets in backward direction
    //

    // Size-based features
    uint64_t total_fwd_bytes;        // Total bytes in forward direction
    uint64_t total_bwd_bytes;        // Total bytes in backward direction
    //

    uint16_t fwd_packet_len_min;     // Min packet size in forward direction
    uint16_t fwd_packet_len_max;     // Max packet size in forward direction
    double   fwd_packet_len_mean;    // Mean packet size in forward direction
    double   fwd_packet_len_std;     // Std dev of packet size in forward direction
    //

    uint16_t bwd_packet_len_min;     // Min packet size in backward direction
    uint16_t bwd_packet_len_max;     // Max packet size in backward direction
    double   bwd_packet_len_mean;    // Mean packet size in backward direction
    double   bwd_packet_len_std;     // Std dev of packet size in backward direction
    //

    // Flow rate features
    double   flow_bytes_per_sec;     // Flow bytes per second
    double   flow_packets_per_sec;   // Flow packets per second
    
    // Inter-Arrival Time features
    double   flow_iat_mean;          // Mean time between packets in the flow
    double   flow_iat_std;           // Std dev of time between packets
    uint64_t flow_iat_max;           // Max time between packets
    uint64_t flow_iat_min;           // Min time between packets
    uint64_t flow_iat_total;         // For then to compute with packet num
    //

    uint64_t fwd_iat_min;            // Min time between forward packets
    uint64_t fwd_iat_max;            // Max time between forward packets
    double   fwd_iat_mean;           // Mean time between forward packets
    double   fwd_iat_std;            // Std dev of time between forward packets
    uint64_t fwd_iat_total;          // Total time between forward packets
    //

    uint64_t bwd_iat_min;            // Min time between backward packets
    uint64_t bwd_iat_max;            // Max time between backward packets
    double   bwd_iat_mean;           // Mean time between backward packets
    double   bwd_iat_std;            // Std dev of time between backward packets
    uint64_t bwd_iat_total;          // Total time between backward packets
    //

    // FWD && BWD Specific flag counts
    uint16_t fwd_psh_flags;          // Number of PSH flags in forward direction
    uint16_t bwd_psh_flags;          // Number of PSH flags in backward direction
    uint16_t fwd_urg_flags;          // Number of URG flags in forward direction
    uint16_t bwd_urg_flags;          // Number of URG flags in backward direction
    //
    
    // Header information
    uint32_t fwd_header_len;         // Total bytes used for headers in forward direction
    uint32_t bwd_header_len;         // Total bytes used for headers in backward direction
    //

    // Packet rate
    double   fwd_packets_per_sec;    // Forward packets per second
    double   bwd_packets_per_sec;    // Backward packets per second
    
    // Aggregate packet length statistics
    uint16_t packet_len_min;         // Minimum length of a packet
    uint16_t packet_len_max;         // Maximum length of a packet
    double   packet_len_mean;        // Mean length of a packet
    double   packet_len_std;         // Std dev of packet length
    double   packet_len_variance;    // Variance of packet length
    //

    // Flag counts
    uint16_t fin_flag_count;         // Number of packets with FIN
    uint16_t syn_flag_count;         // Number of packets with SYN
    uint16_t rst_flag_count;         // Number of packets with RST
    uint16_t psh_flag_count;         // Number of packets with PUSH
    uint16_t ack_flag_count;         // Number of packets with ACK
    uint16_t urg_flag_count;         // Number of packets with URG
    uint16_t cwr_flag_count;         // Number of packets with CWR
    uint16_t ece_flag_count;         // Number of packets with ECE
    //

    // Ratio and averages
    double down_up_ratio;            // Download and upload ratio
    double avg_packet_size;          // Average size of packet
    double fwd_segment_size_avg;     // Average size in forward direction
    double bwd_segment_size_avg;     // Average size in backward direction
    double fwd_segment_size_tot;     // Sum of size in forward direction
    double bwd_segment_size_tot;     // Sum of size in bwd direction
    double fwd_seg_size_min;         // Minimum segment size in forward direction


    // FWD Bulk Features
    bool in_fwd_bulk_transmission;
    int count_possible_fwd_bulk_packets;
    int num_fwd_bulk_transmissions;  // Num of fwd bulk transmissions
    time_t fwd_bulk_start;
    time_t fwd_bulk_end;
    time_t fwd_bulk_duration;
    double fwd_bytes_curr_bulk;    // Total of bytes transmitted in bulk in the forward direction
    double fwd_bytes_bulk_tot;
    double fwd_packet_bulk_tot;    // Total of packet transmitted in bulk in the forward direction
    double fwd_bytes_bulk_avg;     // Average bytes bulk rate in forward direction
    double fwd_packet_bulk_avg;    // Average packet bulk rate in forward direction
    double fwd_bulk_rate_avg;      // Average bulk rate in forward direction
   
    // BWD Bulk features
    bool in_bwd_bulk_transmission;
    int count_possible_bwd_bulk_packets;
    int num_bwd_bulk_transmissions;
    time_t bwd_bulk_start;
    time_t bwd_bulk_end;
    time_t bwd_bulk_duration;
    double bwd_bytes_curr_bulk;
    double bwd_bytes_bulk_tot;
    double bwd_packet_bulk_tot;
    double bwd_bytes_bulk_avg;     // Average bytes bulk rate in backward direction
    double bwd_packet_bulk_avg;    // Average packet bulk rate in backward direction
    double bwd_bulk_rate_avg;      // Average bulk rate in backward direction
    
    // Subflow features
    int total_fwd_subflows;
    uint32_t subflow_fwd_packets;    // Average packets in subflow in forward direction
    uint32_t subflow_fwd_bytes;      // Average bytes in subflow in forward direction
    int total_bwd_subflows;
    uint32_t subflow_bwd_packets;    // Average packets in subflow in backward direction
    uint32_t subflow_bwd_bytes;      // Average bytes in subflow in backward direction
    
    // Window features
    uint32_t fwd_init_win_bytes;     // Initial window bytes in forward direction
    uint32_t bwd_init_win_bytes;     // Initial window bytes in backward direction
    uint32_t fwd_act_data_packets;   // Count of packets with at least 1 byte of TCP data payload
 
    // Active/Idle features
    uint64_t active_time_tot;
    uint64_t curr_active_time_tot;
    uint64_t active_min;             // Minimum time flow was active before becoming idle
    double   active_mean;            // Mean time flow was active before becoming idle
    uint64_t active_max;             // Maximum time flow was active before becoming idle
    double   active_std;             // Std dev of time flow was active before becoming idle
    //


    uint64_t idle_time_tot;          // Current active time, if turns idle:0
    uint64_t curr_idle_time_tot;     // Current idle time, if turns active: 0
    uint64_t idle_min;               // Minimum time flow was idle before becoming active
    double   idle_mean;              // Mean time flow was idle before becoming active
    uint64_t idle_max;               // Maximum time flow was idle before becoming active
    double   idle_std;               // Std dev of time flow was idle before becoming active
    //

    bool classified;
    bool benign;
    float confidence;

} flow_stats_t;

typedef struct {
  uint8_t* data;
  size_t len;
  struct timeval timestamp;
  uint64_t time_microseconds;
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

bool init_model(const char *model_path);

bool initialize_feature_extractor(nids_config_t*);


bool enqueue_packet(const u_char* pkt_data, size_t len, struct timeval timestamp);
bool dequeue_packet(packet_info_t* packet);
#endif /*NIDS_BACKEND_H */
