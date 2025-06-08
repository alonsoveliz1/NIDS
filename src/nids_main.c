#include <json-c/json.h>
#include "nids_backend.h"
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

nids_config_t* config = NULL;
volatile sig_atomic_t running = 0;

/**
 * Sets up logging level and file
 *
 * @return 0 on success, negative on error
 */
static int setup_logging(void);

/**
 * Loads default configuration
 *
 * @return 0 on success, negative on error
 */
static int init_config_defaults(void);

/**
 * Parses cmmd line arguments 
 *
 * @param argc num of params 
 * @param argv array of arguments strings
 * @param config_path Config file path
 *
 * @return 0 on success, negative on error
 */
static int parse_arguments(int argc, char* argv[], char** config_path);

/*
 * Load configuration from the .json config file
 *
 * @param config_path: path to the config.json file
 * 
 * @return 0 on success, negative  on error
 */
int load_config(const char* config_path);

/**
 * Get user's choice for application mode 
 *
 * @return mode (1 = capture, 2 = analysis) on success, -1 on error 
 */
static int get_user_choice(void);

/**
 * Initialize and start all analysis mode components 
 *
 * @return 0 on success, negative on error 
 */
static int start_analysis_mode(void);

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
 * Print ascii Layton banner
 */
void print_ascii_art(void);



int main(int argc, char* argv[]){
    
    if(setup_logging() < 0){
        fprintf(stderr, "Failed to setup logging\n");
        return EXIT_FAILURE;
    }

    log_info("NIDS application starting (PID: %d)", getpid());
    
    if(init_config_defaults() < 0){
        log_fatal("Failed to initilize configuration");
        return EXIT_FAILURE;
    }
   
    char* config_path = NULL;
    if (parse_arguments(argc, argv, &config_path) < 0) {
        log_fatal("Failed to parse command line arguments");
        return EXIT_FAILURE;
    }

    if(config_path != NULL){
        log_info("Loading confguration from: %s", config_path);
        if(load_config(config_path) < 0){
            log_fatal("Failed to load configuration from: %s",config_path);
            return EXIT_FAILURE;
        } else{
            log_info("Configuration loaded successfully");
        }
    } else {
        log_info("Configuration file not found, falling back to default configuration");
    }

    // Setup ctrl+c support & kill
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Print cli ascii art for user choice
    print_ascii_art();
    
    int result = NIDS_OK;
    int mode = get_user_choice();
    switch(mode){
        case 1:
            log_info("Starting capture mode");
            printf("Function not implemented yet, stay tuned in!\n");
            break;
        
        // Start all application module
        case 2:
            log_info("Starting analysis mode");
            result = start_analysis_mode();
            break;
    }

    while(running){
        sleep(1);
    }
    log_info("Shutdown signal received, stopping the program");
    
    if(result < 0){
        log_fatal("Application failed with code %d", result);
        clean_all_processes();
        return EXIT_FAILURE;
    }
    
    log_info("Application completed successfully");
    clean_all_processes();
    return EXIT_SUCCESS;
}



static int setup_logging(void) {
    // Set console logging level
    log_set_level(LOG_WARN);
    //log_add_fp(stdout, LOG_INFO);
    
    // Try to add file logging
    FILE* logfile = fopen("/var/log/nids.log", "a");
    if (logfile) {
        log_add_fp(logfile, LOG_TRACE);
    } else {
        // Just warn, don't fail - console logging is enough
        fprintf(stderr, "Warning: Could not open log file /var/log/nids.log: %s\n", strerror(errno));
        fprintf(stderr, "Continuing with console logging only\n");
    } 
    return NIDS_OK;
}


    
static int init_config_defaults(void) {
    config = malloc(sizeof(nids_config_t));
    if (config == NULL) {
        return NIDS_ERROR;
    }
    
    // Initialize with safe defaults
    memset(config, 0, sizeof(nids_config_t));
    config->interface_name = "enp4s0";
    config->bufsize = 65535;
    config->flow_table_init_size = 10000;
    config->model_path = "../xgboost_model.onnx";
    config->interface_name_dynamic = false;
    config->model_path_dynamic = false;
    
    log_debug("Configuration initialized with defaults");
    return NIDS_OK;
}



static int parse_arguments(int argc, char* argv[], char** config_path) {
    if (!config_path) {
        log_error("Invalid config_path parameter");
        return NIDS_ERROR;
    }
    
    *config_path = NULL;
    int option;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"model", required_argument, 0, 'm'},
        {"config", required_argument, 0, 'c'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((option = getopt_long(argc, argv, "i:m:c:vh", long_options, NULL)) != -1) {
        switch (option) {
            case 'i':
                if (!optarg || strlen(optarg) == 0) {
                    log_error("Interface name cannot be empty");
                    return NIDS_ERROR;
                }
                config->interface_name = optarg;
                log_debug("Interface set to: %s", config->interface_name);
                break;
                
            case 'c':
                if (!optarg || strlen(optarg) == 0) {
                    log_error("Config path cannot be empty");
                    return NIDS_ERROR;
                }
                *config_path = optarg;
                log_debug("Config path set to: %s", *config_path);
                break;
                
            case 'm':
                if (!optarg || strlen(optarg) == 0) {
                    log_error("Model path cannot be empty");
                    return NIDS_ERROR;
                }
                
                // Free previous model path if it was dynamically allocated
                if (config->model_path_dynamic && config->model_path) {
                    free((void*)config->model_path);
                }
                
                config->model_path = strdup(optarg);
                if (!config->model_path) {
                    log_error("Failed to allocate memory for model path");
                    return NIDS_ERROR;
                }
                config->model_path_dynamic = true;
                log_debug("Model path set to: %s", config->model_path);
                break;
                
            case 'v':
                log_set_level(LOG_TRACE);
                log_debug("Verbose logging enabled");
                break;
                
            case 'h':
                printf("Usage: %s [OPTIONS]\n", argv[0]);
                printf("Options:\n");
                printf("  -i, --interface <name>  Network interface to capture from\n");
                printf("  -c, --config <file>     Configuration file path\n");
                printf("  -m, --model <file>      ML model file path\n");
                printf("  -v, --verbose           Enable verbose logging\n");
                printf("  -h, --help              Show this help message\n");
                exit(EXIT_SUCCESS);
                
            case '?':
                log_error("Unknown option or missing argument");
                return NIDS_ERROR;
                
            default:
                log_error("Unexpected getopt return value: %c", option);
                return NIDS_ERROR;
        }
    }
    
    return NIDS_OK;
}



int load_config(const char* config_path){
    if(!config_path){
        log_error("Config path is NULL");
        return NIDS_ERROR;
    }

    struct json_object* json_config = json_object_from_file(config_path);
    if (!json_config) {
        log_error("Failed to parse JSON configuration file: %s", json_util_get_last_err());
        return NIDS_ERROR;
    } 
    //json_object_object_get_ex(struct json_object *, const char *, struct json_object **)
    struct json_object* obj;

    if(json_object_object_get_ex(json_config,"interface", &obj)){
        config->interface_name = strdup(json_object_get_string(obj));
        config->interface_name_dynamic = true;
        log_debug("Loaded interface name: %s", config->interface_name);
    }
    
    if(json_object_object_get_ex(json_config,"bufsize", &obj)){
        config->bufsize = json_object_get_int(obj);
        log_debug("Loaded bufsize: %d", config->bufsize);
    }

    if(json_object_object_get_ex(json_config,"flow_table_init_size", &obj)){
        config->flow_table_init_size = json_object_get_int(obj);
        log_debug("Loaded flow table size: %d", config->flow_table_init_size);
    }

    if(json_object_object_get_ex(json_config, "model_path", &obj)){
        config->model_path = strdup(json_object_get_string(obj));
        config->model_path_dynamic = true;
        log_debug("Loaded model path: %s", config->model_path);
    }
      json_object_put(json_config);
      return NIDS_OK;
}



static int get_user_choice(void){
    int valid = 0;
    int mode = 0;
    while (!valid) {
        printf("Welcome to Layton CLI, what will you be doing today?\n");
        printf("  1) Capture network flow data.\n");
        printf("  2) Analyze network flow data.\n");
        printf("Enter your choice (1-2): ");

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
    return mode;
}



static int start_analysis_mode(void) {
    log_info("Analysis mode selected");
    
    // Initialize all components
    if (init_packet_queue() < 0) {
        log_error("Failed to initialize packet queue");
        return NIDS_ERROR;
    }
    log_debug("Packet queue initialized");
    
    if (init_sniffer() < 0) {
        log_error("Failed to initialize sniffer");
        return NIDS_ERROR;
    }
    log_debug("Sniffer initialized");
    
    if (init_feature_extractor() < 0) {
        log_error("Failed to initialize feature extractor");
        return NIDS_ERROR;
    }
    log_debug("Feature extractor initialized");
    
    if (init_model() < 0) {
        log_error("Failed to initialize model");
        return NIDS_ERROR;
    }
    log_debug("Model initialized");
    
    // Start all components
    if (start_sniffer() < 0) {
        log_error("Failed to start sniffer");
        return NIDS_ERROR;
    }
    log_info("Sniffer started");
    
    if (start_flow_manager() < 0) {
        log_error("Failed to start flow manager");
        return NIDS_ERROR;
    }
    log_info("Flow manager started");
    
    running = 1;
    log_info("Analysis mode running. Press Ctrl+C to stop.");

    return NIDS_OK;
}



static void signal_handler(int sig){
    printf("\nMAIN: Received closing signal: %d. Exiting program gracefully\n", sig);
    running = 0;
}



static void clean_all_processes(){
    printf("MAIN: clean_all_processes function\n");
    
    stop_sniffer();
    stop_flow_manager(); // & clean flow_table
    stop_model();
  
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



