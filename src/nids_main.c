#include <stdio.h>
#include <json-c/json.h>
#include "nids_backend.h"
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

static nids_config_t config;

static bool load_config(const char* config_path);

int main(int argc, char* argv[]){
  /* Default configuration values */
  config.interface_name = "eth0";
  config.bufsize = 65535; // MAX VALUE FOR TCP PACKETS
  
  int options;
  char* config_path = NULL;

  static struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"model", required_argument,0, 'm'},
    {"config", required_argument, 0, 'c'},
    {0,0,0,0}
  };

  while((options = getopt_long(argc, argv, "i:m:c:vh", long_options, NULL)) !=-1){
    switch(options){
      case 'i':
        config.interface_name = optarg;
        break;
      case 'c':
        config_path = optarg;
        break;
    }
  }

  printf("Checking config_path\n");
  if(config_path != NULL){
    printf("Configpath = %s\n",config_path);
    if(!load_config(config_path)){
      fprintf(stderr, "Failed to load configuration file from %s\n", config_path);
      return 1;
    } else{
      printf("Configuration propertly loaded from %s\n", config_path);
    }
  } else {
    printf("Config path is not introducing, using default configuration\n");
  }
  
  if(!initialize_sniffer(&config)){
    printf("Failed to initialize the packet sniffer module\n");
    return 1;
  }

  if(!start_sniffer()){
    fprintf(stderr, "Failed to start the sniffer thread\n");
    return 1;
  }
  
  return 0;
}


static bool load_config(const char* config_path){
  struct json_object* json_config = json_object_from_file(config_path);

  if(!json_config){
    fprintf(stderr, "Error parsing json configuration file %s\n", json_util_get_last_err());
    return false;
  }
  
  //json_object_object_get_ex(struct json_object *, const char *, struct json_object **)
  struct json_object* obj;

  if(json_object_object_get_ex(json_config,"interface", &obj)){
    config.interface_name = strdup(json_object_get_string(obj));
    printf("Interface name %s\n", config.interface_name);
  }
  
  if(json_object_object_get_ex(json_config,"bufsize", &obj)){
    config.bufsize = json_object_get_int(obj);
    printf("Bufsize %d\n", config.bufsize);
  }

  json_object_put(json_config);
  printf("load_config_func exit\n");
  return true;
}
