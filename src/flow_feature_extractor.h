#ifndef FLOW_FEATURE_EXTRACTOR_H
#define FLOW_FEATURE_EXTRACTOR_H

#include "nids_backend.h"

#define IDLE_THRESHOLD 1000000
#define BULK_THRESHOLD 512
#define EXPIRE_THRESHOLD 120000000
#define SUBFLOW_THRESHOLD 15000000
#define CWR_FLAG 0x80
#define ECE_FLAG 0x40

typedef struct flow_entry{
  flow_stats_t stats;
  struct flow_entry* next;
} flow_entry_t;

typedef enum{
  FWD = 1,
  BWD = 2
} flow_direction_t;

/**
 * Get the current number of total flows
 * 
 * @return Number of total flows
 */
int get_flow_count(void);

/**
 * Get the number of processed packets
 * 
 * @return Number of processed packets
 */
int get_packets_processed(void);

/**
 * Force an update of all flows, updating it's time features
 * even if not receiving a new packet
 * 
 * @return true if update was successful, false otherwise
 */

bool update_all_flows(void);


    /**
     * Create a memory pool for flow entries
     * 
     * @param initial_size Initial number of entries to pre-allocate
     * @return Pointer to memory pool or NULL on failure
     
    flow_memory_pool_t* create_flow_memory_pool(size_t initial_size);

    
     * Allocate a flow entry from the memory pool
     * 
     * @param pool Memory pool to allocate from
     * @return Pointer to flow entry or NULL on failure
     
    flow_entry_t* allocate_flow_entry(flow_memory_pool_t* pool);

    
     * Return a flow entry to the memory pool
     * 
     * @param pool Memory pool to return to
     * @param entry Flow entry to return
     
    void free_flow_entry(flow_memory_pool_t* pool, flow_entry_t* entry);

    
     * Process a packet and update flow features
     * 
     * @param data Packet data
     * @param len Packet length
     * @param time_microseconds Packet timestamp in microseconds
     */
 
void process_packet(uint8_t* data, size_t len, uint64_t time_microseconds);

/**
 * Extract a flow key from packet data
 * 
 * @param pkt_data Packet data
 * @param len Packet length
 * @return Pointer to flow key or NULL on failure (caller must free)
 */

flow_key_t* get_flow_key(const u_char* pkt_data, size_t len);

/**
 * Compute a hash value for a flow key
 * 
 * @param key Flow key
 * @return Hash value or UINT32_MAX on failure
 */
uint32_t hash_key(flow_key_t* key);

/**
 * Get a flow from the hash table
 * 
 * @param key Flow key
 * @param flow_hash Hash value for the key
 * @return Pointer to flow statistics or NULL if not found
 */
flow_stats_t* get_flow(flow_key_t* key, uint32_t flow_hash);

/**
 * Create a new flow in the hash table
 * 
 * @param key Flow key
 * @param flow_hash Hash value for the key
 * @param data Packet data
 * @param len Packet length
 * @param time_microseconds Packet timestamp in microseconds
 * @return Pointer to flow statistics or NULL on failure
 */
flow_stats_t* create_flow(flow_key_t* key, uint32_t flow_hash, u_char* data, size_t len, uint64_t time_microseconds);

/**
 * Update an existing flow with a new packet
 * 
 * @param key Flow key
 * @param flow Pointer to flow statistics
 * @param data Packet data
 * @param len Packet length
 * @param time_microseconds Packet timestamp in microseconds
 * @return Pointer to updated flow statistics or NULL on failure
 */
flow_stats_t* update_flow(flow_key_t* key, flow_stats_t* flow, u_char* data, size_t len, uint64_t time_microseconds);

/**
 * Remove an existing flow from the hash map
 *
 * @curr Pointer to pointer to curr flow_entry
 * @prev Pointer to pointer to prev flow_entry
 * @hash_index Position of the bucket where curr is placed
*/
bool remove_flow(struct flow_entry** curr, struct flow_entry** prev, int hash_index);


/**
 * Compute final features for a flow
 * 
 * @param flow Pointer to flow statistics
 */
void compute_cumulative_features(flow_stats_t* flow);

/**
 * Clean up expired flows
 */
void cleanup_expired_flows(void);

/* Helper functions */

/**
 * Get the direction of a packet within a flow
 * 
 * @param flow Pointer to flow statistics
 * @param key Flow key for the packet
 * @return Flow direction (FWD or BWD)
 */
flow_direction_t get_packet_direction(flow_stats_t* flow, flow_key_t* key);

/**
 * Extract TCP flags from packet data
 * 
 * @param data Packet data
 * @param len Packet length
 * @return TCP flags or UINT8_MAX on failure
 */
uint8_t get_tcp_flags(u_char* data, size_t len);

/**
 * Get the header length from packet data
 * 
 * @param data Packet data
 * @param len Packet length
 * @return Header length or UINT32_MAX on failure
 */
uint32_t get_header_len(u_char* data, size_t len);

/**
 * Get the TCP window size from packet data
 * 
 * @param data Packet data
 * @param len Packet length
 * @return Window size or UINT32_MAX on failure
 */
uint32_t get_tcp_window_size(u_char* data, size_t len);

/**
 * Update the running mean and standard deviation using Welford's algorithm
 * 
 * @param count Pointer to count
 * @param mean Pointer to mean
 * @param M2 Pointer to M2 (sum of squared differences)
 * @param new_value New value to incorporate
 */
inline void update_mean_std(uint64_t *count, double *mean, double *M2, double new_value);

/**
 * Compute standard deviation from M2 and count
 * 
 * @param M2 Sum of squared differences
 * @param count Number of values
 * @return Standard deviation
 */
inline double compute_std(double M2, size_t count);

#endif
