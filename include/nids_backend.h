#ifndef NIDS_BACKEND_H
#define NIDS_BACKEND_H
#define NIDS_VERSION "1.0.0"


#define FEATURE_L1_COUNT 37

#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

typedef struct{
  char*   interface_name;
  int     bufsize;
  int     flow_table_init_size;
  char*   model_path;

  bool    interface_name_dynamic;
  bool    model_path_dynamic;
} nids_config_t;

extern nids_config_t* config;

typedef struct{
  uint32_t  src_ip;
  uint32_t  dst_ip;
  uint16_t  src_port;
  uint16_t  dst_port;
  uint8_t   protocol;
} flow_key_t;

typedef enum{
    FLOW_STATUS_ACTIVE = 1,
    FLOW_STATUS_IDLE = 2,
    FLOW_STATUS_CLOSED = 3,
    FLOW_STATUS_EXPIRED = 4
} flow_status_t;

typedef enum{
  CLOSE_STATE_OTHER = 0,             // No closign sequence detected
  CLOSE_STATE_FIN_CLI,               // Cli sent FIN           
  CLOSE_STATE_ACK_FIN_SV,            // Server ACK+FIN
  CLOSE_STATE_ACK_CLI                // Client ACK, end of closing handshake
} flow_close_state_t;


/* Here will go all the features my model needs to class¡fy */
typedef struct{
    flow_key_t key;                  // Key {src_ip, dst_ip, src_port, dst_port, protocol}

    flow_status_t      status;       // Flow [active, idle, closed, expired]
    flow_close_state_t close_state;  // TCP Closing handshake [non-closing, fin-cli, ack_fin_sv, ack_cli] 

    uint32_t  dst_ip_fwd;             // Feature to check if flow is fwd or bwd
    uint32_t  flow_hash;              // Hash of the flow key
    
    // Flow duration
    uint64_t  flow_start_time;        // Start timestamp of the flow
    uint64_t  flow_last_time;         // Last seen timestamp (last packet seen in flow)
    uint64_t  flow_duration;          // Duration of the flow in microseconds 
    uint64_t  last_checked_time;      // Last time that the flow was updated or received a packet 

    // Packet counts
    uint64_t  total_packets;
    uint64_t  total_fwd_packets;      // Total packets in forward direction
    uint64_t  total_bwd_packets;      // Total packets in backward direction

    // Size-based features
    uint64_t  total_bytes;
    uint64_t  total_fwd_bytes;        // Total bytes in forward direction
    uint64_t  total_bwd_bytes;        // Total bytes in backward direction

    uint16_t  fwd_packet_len_min;     // Min packet size in forward direction
    uint16_t  fwd_packet_len_max;     // Max packet size in forward direction
    double    fwd_packet_len_mean;    // Mean packet size in forward direction
    double    fwd_packet_len_std;     // Std dev of packet size in forward direction
    double    fwd_packet_len_M2;       // Variance accumulator

    uint16_t  bwd_packet_len_min;     // Min packet size in backward direction
    uint16_t  bwd_packet_len_max;     // Max packet size in backward direction
    double    bwd_packet_len_mean;    // Mean packet size in backward direction
    double    bwd_packet_len_std;     // Std dev of packet size in backward direction
    double    bwd_packet_len_M2;       // Variance accumulator

    // Flow rate features
    double    flow_bytes_per_sec;     // Flow bytes per second
    double    flow_packets_per_sec;   // Flow packets per second
    
    // Inter-Arrival Time features
    double    flow_iat_mean;          // Mean time between packets in the flow
    double    flow_iat_std;           // Std dev of time between packets
    uint64_t  flow_iat_max;           // Max time between packets
    uint64_t  flow_iat_min;           // Min time between packets
    uint64_t  flow_iat_total;         // For then to compute with packet num
    double    flow_iat_M2;            // Variance accumulator to compute std
    
    // Forward Inter-Arrival
    uint64_t  fwd_iat_min;            // Min time between forward packets
    uint64_t  fwd_iat_max;            // Max time between forward packets
    double    fwd_iat_mean;           // Mean time between forward packets
    double    fwd_iat_std;            // Std dev of time between forward packets
    uint64_t  fwd_iat_total;          // Total time between forward packets
    double    fwd_iat_M2;             // Variance accumulator

    // Backward Inter-Arrival
    uint64_t  bwd_iat_min;            // Min time between backward packets
    uint64_t  bwd_iat_max;            // Max time between backward packets
    double    bwd_iat_mean;           // Mean time between backward packets
    double    bwd_iat_std;            // Std dev of time between backward packets
    uint64_t  bwd_iat_total;          // Total time between backward packets
    double    bwd_iat_M2;             // Variance accumulator

    // FWD && BWD Specific flag counts
    uint16_t  fwd_psh_flags;          // Number of PSH flags in forward direction
    uint16_t  bwd_psh_flags;          // Number of PSH flags in backward direction
    uint16_t  fwd_urg_flags;          // Number of URG flags in forward direction
    uint16_t  bwd_urg_flags;          // Number of URG flags in backward direction
    
    
    // Header information
    uint32_t  fwd_header_len;         // Total bytes used for headers in forward direction
    uint32_t  bwd_header_len;         // Total bytes used for headers in backward direction

    // Packet rate
    double    fwd_packets_per_sec;    // Forward packets per second
    double    bwd_packets_per_sec;    // Backward packets per second
    
    // Aggregate packet length statistics
    uint16_t  packet_len_min;         // Minimum length of a packet
    uint16_t  packet_len_max;         // Maximum length of a packet
    double    packet_len_mean;        // Mean length of a packet
    double    packet_len_std;         // Std dev of packet length
    double    packet_len_variance;    // Variance of packet length
    double    packet_len_M2;           // Variance accumulator

    // Flag counts
    uint16_t  fin_flag_count;         // Number of packets with FIN
    uint16_t  syn_flag_count;         // Number of packets with SYN
    uint16_t  rst_flag_count;         // Number of packets with RST
    uint16_t  psh_flag_count;         // Number of packets with PUSH
    uint16_t  ack_flag_count;         // Number of packets with ACK
    uint16_t  urg_flag_count;         // Number of packets with URG
    uint16_t  cwr_flag_count;         // Number of packets with CWR
    uint16_t  ece_flag_count;         // Number of packets with ECE
    //

    // Ratio and averages
    double  down_up_ratio;            // Download and upload ratio (total_bwd_bytes/total_fwd_bytes)
    double  avg_packet_size;          // Average size of packet
    double  fwd_segment_size_avg;     // Average size in forward direction
    double  bwd_segment_size_avg;     // Average size in backward direction
    double  fwd_segment_size_tot;     // Sum of size in forward direction
    double  bwd_segment_size_tot;     // Sum of size in bwd direction
    double  fwd_seg_size_min;         // Minimum segment size in forward direction


    // FWD Bulk Features
    bool    in_fwd_bulk_transmission;       // Variable to check whether being inside a bulk transmission or not
    int     count_possible_fwd_bulk_packets; // Accumulator oc bulk packets transmitted in a row
    int     num_fwd_bulk_transmissions;      // Num of fwd bulk transmissions
    time_t  fwd_bulk_start;               // Current fwd bulk transmission start
    time_t  fwd_bulk_end;                 // Current fwd bulk transmission end
    time_t  fwd_bulk_duration;            // Total fwd bulk duration accumulator
    double  fwd_bytes_curr_bulk;          // Total of bytes transmitted in the current bulk in the forward direction
    double  fwd_bytes_bulk_tot;           // Total of bytes transmitted in bulk in the forward direction
    double  fwd_packet_bulk_tot;          // Total of packet transmitted in bulk in the forward direction
    double  fwd_bytes_bulk_avg;           // Average bytes bulk rate in forward direction
    double  fwd_packet_bulk_avg;          // Average packet bulk rate in forward direction
    double  fwd_bulk_rate_avg;            // Average bulk rate in forward direction
   
    // BWD Bulk Features
    bool    in_bwd_bulk_transmission;       // Variable to check whether being inside a bulk transmission or not
    int     count_possible_bwd_bulk_packets; // Accumulator of bulk packets transmitted in a row
    int     num_bwd_bulk_transmissions;      // Num of bwd bulk transmissions
    time_t  bwd_bulk_start;               // Current bwd bulk transmission start
    time_t  bwd_bulk_end;                 // Current bwd bulk transmission end
    time_t  bwd_bulk_duration;            // Total bwd bulk duration accumulator
    double  bwd_bytes_curr_bulk;          // Total of bytes transmitted in the current bulk in the backward direction
    double  bwd_bytes_bulk_tot;           // Total of bytes transmitted in bulk in the backward direction
    double  bwd_packet_bulk_tot;          // Total of packets transmitted in bulk in the backward direction
    double  bwd_bytes_bulk_avg;           // Average bytes bulk rate in backward direction
    double  bwd_packet_bulk_avg;          // Average packet bulk rate in backward direction
    double  bwd_bulk_rate_avg;            // Average bulk rate in backward direction
 
    // Subflow features
    int       total_fwd_subflows;          // Total subflows in fwd direction
    uint32_t  subflow_fwd_packets;    // Average packets in subflow in forward direction
    uint32_t  subflow_fwd_bytes;      // Average bytes in subflow in forward direction
    int       total_bwd_subflows;          // Total subflows in bwd direction
    uint32_t  subflow_bwd_packets;    // Average packets in subflow in backward direction
    uint32_t  subflow_bwd_bytes;      // Average bytes in subflow in backward direction
    
    // Window features
    uint32_t  fwd_init_win_bytes;     // Initial window bytes in forward direction
    uint32_t  bwd_init_win_bytes;     // Initial window bytes in backward direction
    uint32_t  fwd_act_data_packets;   // Count of packets with at least 1 byte of TCP data payload
 
    // Active/Idle features
    uint64_t  active_counts;
    uint64_t  active_time_tot;
    uint64_t  curr_active_time_tot;
    uint64_t  active_min;             // Minimum time flow was active before becoming idle
    double    active_mean;            // Mean time flow was active before becoming idle
    uint64_t  active_max;             // Maximum time flow was active before becoming idle
    double    active_std;             // Std dev of time flow was active before becoming idle
    double    active_time_M2;       // Variance accumulator

    uint64_t idle_counts;
    uint64_t idle_time_tot;          // Current active time, if turns idle:0
    uint64_t curr_idle_time_tot;     // Current idle time, if turns active: 0
    uint64_t idle_min;               // Minimum time flow was idle before becoming active
    double   idle_mean;              // Mean time flow was idle before becoming active
    uint64_t idle_max;               // Maximum time flow was idle before becoming active
    double   idle_std;               // Std dev of time flow was idle before becoming active
    double   idle_time_M2;           // Variance accumulator

    bool serv_http;                  // HTTP Service (port 80, 81, 8000, 8081)
    bool serv_https;                 // HTTPS Service (port 443)
    bool serv_mqtt;                  // MQTT Service (port 1883)
    bool serv_other;                 // Other service (rest of the ports)
    bool serv_iot_port;              // IoT Service (ports 8000-9000)
    bool serv_ephimeral;             // Ephemeral port (49152-65535)
    bool serv_ssh;                   // SSH service (port 22) 

    time_t classification_time;
    bool classified;                 // Flow has been classified
    bool benign;                     // Flow is benign
    float confidence;                // Classification confidence
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


/*******************************************************                                                     
 *                      SNIFFER.c                      *                                       
 *******************************************************/


/**
 * Caller function to open the config pcapture interface and set bpf capture filter to tcp-ip
 *
 * @return true if interface opened successfully false otherwise 
 */
bool initialize_sniffer();

/**
 * Caller function to start sniffer thread with its function
 *
 * @return true if created successfully false otherwise
 */
bool start_sniffer();

/** 
 * Caller function to stop the sniffer thread 
 */
void stop_sniffer();

/*******************************************************                                                     
 *               FLOW_FEATURE_EXTRACTOR.c              *                                       
 *******************************************************/


/**
 * Caller function to initialize the flow feature extractor
 * allocating memory for the flow_hashmap
 * 
 * @return true if initialization successful, false otherwise
 */
bool initialize_feature_extractor();

/**
 * Start the flow manager thread
 * 
 * @return true if thread started successfully, false otherwise
 */
bool start_flow_manager();

/**
 * Stop the flow manager thread and clean up resources
 */
void stop_flow_manager(void);


/*******************************************************                                                     
 *                    FLOW_ANALYSER.c                  *                                       
 *******************************************************/


/**
 * Caller function to initialize the ONNX Runtime model
 *
 * @return true in case model started successfully false otherwise
 */
bool initialize_model();

/**
 * Classify flow (benign, malicious) with the ONNX model
 *
 * @param flow Pointer to flow_stats struct with flow information
 * @return 1 if flow is malicious and 0 if benign
 */ 
int classify_flow(flow_stats_t* flow);

/**
 * Caller function to stop the ONNX Runtime model, freeing input & output_names
 * and releasing session options & env
 *
 * @return true if model was succesfully terminated
 */

/**
 * Classify flow (benign, malicious) with the ONNX model TEST FUNCTION
 *
 * @param flow Pointer to flow_stats struct with flow information
 * @return 1 if flow is malicious and 0 if benign
 */ 
int test_classify_flow(float* parsed_features);

bool stop_model();


/*******************************************************                                                     
 *                    PACKET_QUEUE.c                   *                                       
 *******************************************************/

/**
 * Initialize packet queue mutex, not empty & not full conds 
 *
 * @return true if done properly false otherwise 
 */
bool init_packet_queue();

bool enqueue_packet(const u_char* pkt_data, size_t len, struct timeval timestamp);
bool dequeue_packet(packet_info_t* packet);
#endif /*NIDS_BACKEND_H */
