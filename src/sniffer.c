#include <pcap.h>
#include <pthread.h>
#include "nids_backend.h"

// State variables
static bool sniffer_running;

// Sniffer thread handle
static pthread_t sniffer_thread;

static pcap_t* pcap_handle = NULL;
struct bpf_program fp;

/*
 * Function executed by the sniffer thread. 
 * Sets up properties and runs the packet capture loop until stopped 
 *
 * @return NULL always 
 */
static void* sniff_thread_func();

/*
 * Callback function that processed each captured packet, called by pcap_loop for each packet 
 * that matches the BPF (TCP) 
 *
 * @param pkthdr Pointer to packet header containing metadata
 * @param packet pointer to the raw packet buffer 
 *
 */
static void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);



int init_sniffer(void){
    if(!config){
        log_fatal("Invalid configuration pointer");
        return NIDS_ERROR;
    }
    // Opening packet capture interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(config->interface_name, config->bufsize, 1, 1000, errbuf);
    if(pcap_handle == NULL){
        log_fatal("Error opening interface %s: %s", config->interface_name, errbuf);
        return NIDS_ERROR;
    }
    
    int dlt = pcap_datalink(pcap_handle);
    log_info("Detected datalink layer type: %s", pcap_datalink_val_to_name(dlt));
    
    // Compiling bpf to capture only tcp packets
    char filter_exp[] = "tcp";
    if(pcap_compile(pcap_handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) != 0){
        log_fatal("Error compiling berkeley-packet-filter expression");
        return NIDS_ERROR;
    }
    
    // Set its filter
    if(pcap_setfilter(pcap_handle, &fp) == -1){
        log_fatal("Error setting up the filter: %s", filter_exp);
        return NIDS_ERROR;
    }
    log_info("Interface: %s succesfully opened", config->interface_name);
    return NIDS_OK;
}



int start_sniffer(){
    if(pcap_handle == NULL){
        log_fatal("Can't start the sniffer module cause handler is not instanciated");
        return NIDS_ERROR;
    }

    if(sniffer_running){
        log_error("Can't start packet sniffer cause it's already running");
        return NIDS_ERROR;
    }

    // CODE TO START THE SNIFFER THREAD
    if(pthread_create(&sniffer_thread, NULL, &sniff_thread_func, NULL) != 0){
        pcap_close(pcap_handle);
        pcap_handle = NULL;
        log_fatal("Sniffer thread couldnt be created properly");
        sniffer_running = false;
        return NIDS_ERROR;
    }

    sniffer_running = true;
    return NIDS_OK; 
}



int stop_sniffer(){
    if(!sniffer_running){
        log_error("Cant stop the sniffer module when it isnt runnign");
        return NIDS_ERROR;
    }
  
    sniffer_running = false;
    pcap_breakloop(pcap_handle);
    pthread_join(sniffer_thread, NULL); // Properly cleaning up the thread and not having a zombi process

    if(pcap_handle != NULL){
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }

    pcap_freecode(&fp);
    log_info("Succesfully stopped the sniffer thread");
    return NIDS_OK;
}



static void* sniff_thread_func(){
    log_info("Hello from inside sniff thread function");

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setname_np(pthread_self(), "sniff_thread");

    /* pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) */
    int pcap_loop_state = pcap_loop(pcap_handle, 0, packet_handler , NULL);
    if(pcap_loop_state == -1){
        log_error("Pcap_loop init error: %s", pcap_geterr(pcap_handle));
    } else if(pcap_loop_state == 0){
        log_info("Pcap_loop ended succesfully");
    }
    return NULL;
}



static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
    log_info("Packet captured");
    if(enqueue_packet(pkt_data, header->len, header->ts) < 0){
        log_error("Failed to enqueue packet");
  }
}

 

