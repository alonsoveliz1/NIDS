#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

// Define the structure
typedef struct {
    char* interface_name;
    bool interface_name_dynamic;
    int bufsize;
    int flow_table_init_size;
    char* model_path;
    bool model_path_dynamic;
} nids_config_t;

extern nids_config_t* config;

bool load_config(const char* config_path);

#endif

