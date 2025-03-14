#include <stdio.h>
#include <json-c/json.h>
#include "nids_backend.h"
#include <stdbool.h>
#include <string.h>


static nids_config_t config;

static bool load_config(const char* config_path);

int main(int argc, char* argv[]){
  /* Default configuration values */
  config.interface_name = "eth0";

  char* config_path = NULL;

  if(config_path != NULL){
    if(!load_config(config_path)){
      fprintf(stderr, "Failed to load configuration file from %s\n", config_path);
      return 1;
    }
  }
  return 0;
}


static bool load_config(const char* config_path){
  json_object* json_config = json_object_from_file(config_path);

  if(!json_config){
    fprintf(stderr, "Error parsing json configuration file %s\n", json_util_get_last_err());
    return false;
  }
  
  //json_object_object_get_ex(struct json_object *, const char *, struct json_object **)
  struct json_object* obj;

  if(json_object_object_get_ex(json_config,"interface", &obj)){
    config.interface_name = strdup(json_object_get_string(obj));
  }

  json_object_put(json_config);

  return true;
}
