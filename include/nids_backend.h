#ifndef NIDS_BACKEND_H
#define NIDS_BACKEND_H

#include <stdbool.h>
typedef struct{
  char* interface_name;
  int bufsize;
} nids_config_t;

typedef struct{
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  //ISN del flujo para identificarlo
} flow_key_t;

/* Inicializacion del sistema */
bool init_nids(nids_config_t* config);
/* Terminacion del sistema */ 

/* Initialization sniffer */
bool initialize_sniffer(nids_config_t* config);
/* Terminacion del sniffer */

bool start_sniffer(void);
static void* sniff_thread(void*); // ESTO TENGO QUE MIRARLO (void*)

#endif /*NIDS_BACKEND_H */
