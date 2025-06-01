#include <json-c/json.h>
#include "nids_backend.h"
#include <string.h>
#include <getopt.h>
#include <unistd.h>

nids_config_t* config = NULL;
volatile sig_atomic_t running = 0;


/**
 * Load configuration from the .json config file
 *
 * @param config_path: path to the config.json file
 */
bool load_config(const char* config_path);

/**
 * Signal handler to stop the backend on SIGINT and SIGTERM
 *
 * @param sig: Signal code
 */
static void signal_handler(int sig);

/**
 * Shutdown orchestrator of all the clean_all_processes
 */
static void clean_all_processes(void);

/**
 *
 * Print ascii Layton app 
 */
void print_ascii_art(void);


int main(int argc, char* argv[]){

    config = malloc(sizeof(nids_config_t));
    if(config == NULL){
        fprintf(stderr, "Failed to allocate memory for config\n");
        return 1;
    }

    /* Default configuration values */
    config->interface_name = "eth0";
    config->bufsize = 65535; // MAX VALUE FOR TCP PACKETS
    config->flow_table_init_size = 10000;
    config->model_path = "../xgboost_model.onnx"; 

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
            config->interface_name = optarg;
            break;
        case 'c':
            config_path = optarg;
          break;
        case 'm':
            strcpy(config->model_path, optarg);
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
        printf("Config path is not introduced, using default configuration\n");
    }

    printf("My PID is: %d\n", getpid());

    // Setup ctrl+c support & kill
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Print cli ascii art
    print_ascii_art();
 
    int valid = 0;
    int mode = 0;
    while (!valid) {
        printf("Welcome to Layton CLI, what will you be doing today?\n");
        printf("  1) Capture network flow data.\n");
        printf("  2) Analyze network flow data.\n");
        printf("Enter your choice: ");

      if (scanf("%d", &mode) != 1) {
          // Clear invalid input
          while (getchar() != '\n'); // flush the input buffer
          printf("Invalid input. Please enter a number.\n\n");
          continue;
      }

      if (mode == 1) {
          printf("Starting capture module...\n");
          valid = 1;
      } else if (mode == 2) {
          printf("Starting analysis module...\n");
          valid = 1;
      } else {
          printf("Invalid option. Please select 1 or 2.\n\n");
          while(getchar() != '\n');
      }
  }
      
  switch(mode){
    case 1:
        printf("Function not implemented yet, stay tuned in!\n");
        break;
    
    // Start all application module
    case 2:
      if(!init_packet_queue()){
          fprintf(stderr, "Failed to initialize the queue mutex\n");
          return 1;
      }

    if(!init_sniffer()){
        fprintf(stderr, "Failed to initialize the packet sniffer module\n");
        return 1;
    }
    
    if(!init_feature_extractor()){
        fprintf(stderr, "Failed to initialize the flow feature extractor module\n");
        return 1;
    }
    
    if(!init_model()){
        fprintf(stderr, "Failed to start the model");
        return 1;
    }

    running = 1;

    if(!start_sniffer()){
      fprintf(stderr, "Failed to start the sniffer thread\n");
      return 1;
    }

    if(!start_flow_manager()){
      fprintf(stderr, "Failed to start the feature manager thread\n");
      return 1;
    }

    while(running){
      sleep(1);
    }

    printf("MAIN: Shutting down the program...\n");
    clean_all_processes();
    return 0;
    
  } 

  return 0;

}

/*
* Reads the config.json file and updates the params included in them
* 
* @param config_path pointer to path where the configuration file is located
*/
bool load_config(const char* config_path){ 
    struct json_object* json_config = json_object_from_file(config_path);

    if(!json_config){
        fprintf(stderr, "Error parsing json configuration file %s\n", json_util_get_last_err());
        return false;
    }
    
    //json_object_object_get_ex(struct json_object *, const char *, struct json_object **)
    struct json_object* obj;

    if(json_object_object_get_ex(json_config,"interface", &obj)){
        config->interface_name = strdup(json_object_get_string(obj));
        config->interface_name_dynamic = true;
        printf("Interface name %s\n", config->interface_name);
    }
    
    if(json_object_object_get_ex(json_config,"bufsize", &obj)){
        config->bufsize = json_object_get_int(obj);
        printf("Bufsize %d\n", config->bufsize);
    }

    if(json_object_object_get_ex(json_config,"flow_table_init_size", &obj)){
        config->flow_table_init_size = json_object_get_int(obj);
        printf("Flow table init size %d\n", config->flow_table_init_size);
    }

    if(json_object_object_get_ex(json_config, "model_path", &obj)){
        config->model_path = strdup(json_object_get_string(obj));
        config->model_path_dynamic = true;
        printf("Model_path %s\n", config->model_path);
    }
      json_object_put(json_config);
      printf("load_config_func exit\n");
      return true;
  }

/* 
* Sets global running variable to 0 
*
* @param signal received, sigint or sigterm 
*/
static void signal_handler(int sig){
    printf("\nMAIN: Received closing signal: %d. Exiting program gracefully\n", sig);
    running = 0;
}

/*
* Function to orchestrate closing process 
* 
* stops all threads waking up the ones locked in a mutex condition, then frees memory 
* allocated by the packet queue, flow hash_map and configuration file 
*/
static void clean_all_processes(){
    printf("MAIN: clean_all_processes function\n");

    stop_sniffer();
    stop_flow_manager();
    stop_model();
   
    //clean_flow_hashmap();
    clean_packet_queue();

    if(config != NULL){
      if(config->interface_name != NULL && config->interface_name_dynamic) free(config->interface_name);
      if(config->model_path != NULL && config->model_path_dynamic) free(config->model_path);
      free(config);
      config = NULL;
    }
}


void print_ascii_art(void){
char *layton =
" __                         __                      \n"
"/\\ \\                       /\\ \\__                   \n"
"\\ \\ \\         __     __  __\\ \\ ,_\\   ___     ___    \n"
" \\ \\ \\  __  /'__`\\  /\\ \\/\\ \\\\ \\ \\/  / __`\\ /' _ `\\  \n"
"  \\ \\ \\L\\ \\/\\ \\L\\.\\_\\ \\ \\_\\ \\\\ \\ \\_/\\ \\L\\ \\/\\ \\/\\ \\ \n"
"   \\ \\____/\\ \\__/.\\_\\\\/`____ \\\\ \\__\\ \\____/\\ \\_\\ \\_\\\n"
"    \\/___/  \\/__/\\/_/ `/___/> \\\\/__/\\/___/  \\/_/\\/_/\n"
"                         /\\___/                     \n"
"                         \\/__/                      \n";
    printf("%s", layton);
}


