#include "nids_backend.h"
#include "onnxruntime_c_api.h"
#include <string.h>


static bool model_running = false;

// ONNX Runtime Api handles and objects
static const OrtApi *ort_api = NULL;
static OrtEnv *ort_env = NULL;
static OrtSessionOptions *options = NULL;
static OrtSession *session = NULL;
static OrtAllocator *ort_allocator = NULL;
static size_t input_count = 0;
static size_t output_count = 0;
static char **input_names = NULL;
static char **output_names = NULL;

/*
* Function to check if there's any problem in each step of setting up the prediction model 
* 
* @param status handle updated each ONNX operation
*/
static void check_status(OrtStatus *status);
void extract_l1_features(flow_stats_t *flow, float *input_l1_values);

static void check_status(OrtStatus *status){
    if(status != NULL){
        const char* msg = ort_api->GetErrorMessage(status);
        log_error("ONNX Runtime Error: %s", msg);
        ort_api->ReleaseStatus(status);
        exit(1); 
    }
}



int init_model() {
    log_info("Starting model initialization...");
    
    if (model_running) {
        log_warn("Model is already running");
        return NIDS_OK;
    }
    
    OrtStatus *status = NULL;

    // Get ONNX Runtime API
    ort_api = OrtGetApiBase()->GetApi(ORT_API_VERSION);
    if (!ort_api) {
        log_fatal("Failed to get the ONNX Runtime API");
        return NIDS_ERROR;
    }
    log_info("ONNX Runtime API obtained successfully (version: %d)", ORT_API_VERSION);

    // Create ONNX environment (context) with logging level and identifier
    status = ort_api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "nids-model", &ort_env);
    if (status != NULL) {
        log_fatal("Failed to create ONNX environment");
        check_status(status);
        return NIDS_ERROR;
    }
    log_info("ONNX environment created successfully");
    
    // Create session options
    status = ort_api->CreateSessionOptions(&options);
    if (status != NULL) {
        log_fatal("Failed to create session options");
        check_status(status);
        return NIDS_ERROR;
    }
    log_info("Session options created successfully");
    
    // Set number of threads for intra-operation parallelism
    status = ort_api->SetIntraOpNumThreads(options, 1);
    if (status != NULL) {
        log_error("Failed to set intra-op threads");
        check_status(status);
        return NIDS_ERROR;
    }
    log_info("Intra-op threads set to 1");

    // Create session -> loading model from disk to memory
    log_info("Loading model from: %s", config->model_path);
    status = ort_api->CreateSession(ort_env, config->model_path, options, &session);
    if (status != NULL) {
        log_fatal("Failed to create ONNX session - model loading failed");
        check_status(status);
        return NIDS_ERROR;
    }
    log_info("ONNX session created successfully - model loaded!");
    
    // Get default allocator
    status = ort_api->GetAllocatorWithDefaultOptions(&ort_allocator);
    if (status != NULL) {
        log_fatal("Failed to get allocator");
        check_status(status);
        return NIDS_ERROR;
    }
    log_info("Allocator obtained successfully");

    // Get input count
    status = ort_api->SessionGetInputCount(session, &input_count);
    if (status != NULL) {
        log_fatal("Failed to get input count");
        check_status(status);
        return NIDS_ERROR;
    }
    log_info("Model input count: %zu", input_count);
    
    // Get output count
    status = ort_api->SessionGetOutputCount(session, &output_count);
    if (status != NULL) {
        log_fatal("Failed to get output count");
        check_status(status);
        return NIDS_ERROR;
    }
    log_info("Model output count: %zu", output_count);
    
    // Validate input/output counts
    if (input_count == 0 || output_count == 0) {
        log_fatal("Invalid model: input_count=%zu, output_count=%zu", input_count, output_count);
        return NIDS_ERROR;
    }
    
    // Allocate memory for input names
    input_names = (char**)malloc(sizeof(char*) * input_count);
    if (!input_names) {
        log_fatal("Failed to allocate memory for input names");
        return NIDS_ERROR;
    }
    log_info("Input names array allocated successfully");

    // Get input names
    for (size_t i = 0; i < input_count; i++) {
        status = ort_api->SessionGetInputName(session, i, ort_allocator, &input_names[i]);
        if (status != NULL) {
            log_fatal("Failed to get input name %zu", i);
            check_status(status);
            return NIDS_ERROR;
        }
        log_debug("Input %zu: %s", i, input_names[i]);
    }
    log_info("Input names retrieved successfully");

    // Allocate memory for output names
    output_names = (char**)malloc(sizeof(char*) * output_count);
    if (!output_names) {
        log_fatal("Failed to allocate memory for output names");
        return NIDS_ERROR;
    }
    log_info("Output names array allocated successfully");

    // Get output names
    for (size_t i = 0; i < output_count; i++) {
        status = ort_api->SessionGetOutputName(session, i, ort_allocator, &output_names[i]);
        if (status != NULL) {
            log_fatal("Failed to get output name %zu", i);
            check_status(status);
            return NIDS_ERROR;
        }
        log_debug("Output %zu: %s", i, output_names[i]);
    }
    log_info("Output names retrieved successfully");
    
    model_running = true;
    log_info("Model initialization completed successfully!");
    return NIDS_OK;
}



int classify_flow(flow_stats_t* flow){
    if(!flow){
        log_error("Error null pointer received in classify flow");
        return NIDS_ERROR;
    }
   
    struct timespec t1;
    clock_gettime(CLOCK_REALTIME, &t1);

    OrtStatus *status = NULL;
    OrtValue *input_tensor = NULL;
    OrtValue *output_tensor = NULL;
    
    const int64_t input_dims[] = {1, FEATURE_L1_COUNT};
    float input_values[FEATURE_L1_COUNT];
    float *output_values = NULL;

    extract_l1_features(flow, input_values);
   
    // Create input tensor object from data values 
    OrtMemoryInfo *memory_info;
    status = ort_api->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &memory_info);
    check_status(status);


    status = ort_api->CreateTensorWithDataAsOrtValue(memory_info, input_values, sizeof(float) * FEATURE_L1_COUNT,
                                                     input_dims, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &input_tensor);
    check_status(status);
    
 
    const OrtValue* input_tensors[] = {input_tensor};

    status = ort_api->Run(session, NULL,  (const char* const*)input_names, input_tensors, input_count, (const char* const*)output_names, output_count, &output_tensor);
    check_status(status);

    int prediction = -1;
    status = ort_api->GetTensorMutableData(output_tensor, (void**)&output_values);
    check_status(status);

    struct timespec t2;
    clock_gettime(CLOCK_REALTIME, &t2); 
    uint64_t t1_ns = t1.tv_sec * 1000000000ULL + t1.tv_nsec;
    uint64_t t2_ns = t2.tv_sec * 1000000000ULL + t2.tv_nsec;
    uint64_t time_ns = t2_ns - t1_ns;
    printf("Prediction time: %.1f μs (%.3f ms)\n", time_ns / 1000.0, time_ns / 1000000.0);

    if (output_values[0] > output_values[1]) {
        printf("PREDICTION 0\n");
        prediction = 0; // Normal traffic
    } else {
        prediction = 1; // Attack traffic
        printf("PREDICTION 1\n");
    }

    if (memory_info) ort_api->ReleaseMemoryInfo(memory_info);
    if (input_tensor) ort_api->ReleaseValue(input_tensor);
    if (output_tensor) ort_api->ReleaseValue(output_tensor);

    return prediction;
}

int test_classify_flow(float *input_values){
    if(!input_values){
        fprintf(stderr, "Error null pointer received in input_values");
        return NIDS_ERROR;
    }
   
    struct timespec t1;
    clock_gettime(CLOCK_REALTIME, &t1);

    OrtStatus *status = NULL;
    OrtValue *input_tensor = NULL;
    OrtValue *output_tensor = NULL;
    
    const int64_t input_dims[] = {1, FEATURE_L1_COUNT};
    float *output_values = NULL;
 
    // Create input tensor object from data values 
    OrtMemoryInfo *memory_info;
    status = ort_api->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &memory_info);
    check_status(status);


    status = ort_api->CreateTensorWithDataAsOrtValue(memory_info, input_values, sizeof(float) * FEATURE_L1_COUNT,
                                                     input_dims, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &input_tensor);
    check_status(status);
    
    const OrtValue* input_tensors[] = {input_tensor};

    status = ort_api->Run(session, NULL,  (const char* const*)input_names, input_tensors, input_count, (const char* const*)output_names, output_count, &output_tensor);
    check_status(status);

    int prediction = -1;
    status = ort_api->GetTensorMutableData(output_tensor, (void**)&output_values);
    check_status(status);

    struct timespec t2;
    clock_gettime(CLOCK_REALTIME, &t2);

    uint64_t t1_ns = t1.tv_sec * 1000000000ULL + t1.tv_nsec;
    uint64_t t2_ns = t2.tv_sec * 1000000000ULL + t2.tv_nsec;
    uint64_t time_ns = t2_ns - t1_ns;
    printf("Prediction time: %.1f μs (%.3f ms)\n", time_ns / 1000.0, time_ns / 1000000.0);

    if (output_values[0] > output_values[1]) {
        printf("PREDICTION 0\n");
        prediction = 0; // Normal traffic
    } else {
        prediction = 1; // Attack traffic
        printf("PREDICTION 1\n");
    }

    if (memory_info) ort_api->ReleaseMemoryInfo(memory_info);
    if (input_tensor) ort_api->ReleaseValue(input_tensor);
    if (output_tensor) ort_api->ReleaseValue(output_tensor);

    return prediction;
}



bool stop_model(){
    OrtStatus *close_status;

    if(!model_running){
        log_warn("Can't stop model when it's not running");
        return NIDS_OK;
    }

    for(size_t i = 0; i < input_count; i++){
        close_status = ort_api->AllocatorFree(ort_allocator, input_names[i]);
        check_status(close_status);
    }

    
    for(size_t j =0; j < output_count; j++){
        close_status = ort_api->AllocatorFree(ort_allocator, output_names[j]);
        check_status(close_status);
    }
    
    free(input_names);
    free(output_names);

    ort_api->ReleaseSession(session);
    ort_api->ReleaseSessionOptions(options);
    ort_api->ReleaseEnv(ort_env);
    
    model_running = false;
    return true; 
}


void extract_l1_features(flow_stats_t *flow, float *input_l1_values){
    
    int idx = 0;
    
    input_l1_values[idx++] = (float)flow->flow_duration;
    input_l1_values[idx++] = (float)flow->total_fwd_packets;
    input_l1_values[idx++] = (float)flow->total_fwd_bytes;
    input_l1_values[idx++] = (float)flow->total_bwd_bytes;
    input_l1_values[idx++] = (float)flow->fwd_packet_len_min;
    input_l1_values[idx++] = (float)flow->fwd_packet_len_std;
    input_l1_values[idx++] = (float)flow->bwd_packet_len_max;
    input_l1_values[idx++] = (float)flow->bwd_packet_len_min;
    input_l1_values[idx++] = (float)flow->bwd_packet_len_mean;
    input_l1_values[idx++] = (float)flow->flow_bytes_per_sec;
    input_l1_values[idx++] = (float)flow->flow_packets_per_sec;
    input_l1_values[idx++] = (float)flow->flow_iat_mean;
    input_l1_values[idx++] = (float)flow->flow_iat_std;
    input_l1_values[idx++] = (float)flow->fwd_iat_total;
    input_l1_values[idx++] = (float)flow->fwd_iat_mean;
    input_l1_values[idx++] = (float)flow->fwd_iat_std;
    input_l1_values[idx++] = (float)flow->fwd_iat_max;
    input_l1_values[idx++] = (float)flow->fwd_iat_min;
    input_l1_values[idx++] = (float)flow->bwd_iat_total;
    input_l1_values[idx++] = (float)flow->bwd_iat_mean;
    input_l1_values[idx++] = (float)flow->bwd_iat_std;
    input_l1_values[idx++] = (float)flow->bwd_iat_max;
    input_l1_values[idx++] = (float)flow->fwd_psh_flags;
    input_l1_values[idx++] = (float)flow->fwd_urg_flags;
    input_l1_values[idx++] = (float)flow->bwd_packets_per_sec;
    input_l1_values[idx++] = (float)flow->packet_len_min;
    input_l1_values[idx++] = (float)flow->packet_len_max;
    input_l1_values[idx++] = (float)flow->packet_len_mean;
    input_l1_values[idx++] = (float)flow->packet_len_variance;
    input_l1_values[idx++] = (float)flow->fin_flag_count;
    input_l1_values[idx++] = (float)flow->syn_flag_count;
    input_l1_values[idx++] = (float)flow->rst_flag_count;
    input_l1_values[idx++] = (float)flow->psh_flag_count;
    input_l1_values[idx++] = (float)flow->urg_flag_count;
    input_l1_values[idx++] = (float)flow->cwr_flag_count;
    input_l1_values[idx++] = (float)flow->ece_flag_count;
    input_l1_values[idx++] = (float)flow->down_up_ratio;
    input_l1_values[idx++] = (float)flow->bwd_bytes_bulk_avg;
    input_l1_values[idx++] = (float)flow->bwd_packet_bulk_avg;
    input_l1_values[idx++] = (float)flow->bwd_bulk_rate_avg;
    input_l1_values[idx++] = (float)flow->subflow_fwd_packets;
    input_l1_values[idx++] = (float)flow->subflow_fwd_bytes;
    input_l1_values[idx++] = (float)flow->subflow_bwd_bytes;
    input_l1_values[idx++] = (float)flow->fwd_init_win_bytes;
    input_l1_values[idx++] = (float)flow->bwd_init_win_bytes;
    input_l1_values[idx++] = (float)flow->fwd_seg_size_min;
    input_l1_values[idx++] = (float)flow->active_std;
    input_l1_values[idx++] = (float)flow->active_max;
    input_l1_values[idx++] = (float)flow->idle_std;
    input_l1_values[idx++] = (float)flow->idle_min;
    input_l1_values[idx++] = flow->serv_custom_service   ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_ephimeral         ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_http              ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_http_alt          ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_https             ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_irc               ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_common_iot               ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_iot_gateway       ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_mqtt              ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_other             ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_rtsp              ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_remote_shell      ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_ssh               ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_telnet            ? 1.0f : 0.0f;
    input_l1_values[idx++] = flow->serv_unknown_app       ? 1.0f : 0.0f;
}



