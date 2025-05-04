#include "onnxruntime_c_api.h"
#include <stdio.h>
#include "nids_backend.h"
#include <string.h>

#define FEATURE_L1_COUNT 37

static const OrtApi *ort_api = NULL;
static OrtEnv *ort_env = NULL;
static OrtSessionOptions *options = NULL;
static OrtSession *session = NULL;
static OrtAllocator *ort_allocator = NULL;
static size_t input_count = 0;
static size_t output_count = 0;
static char **input_names = NULL;
static char **output_names = NULL;

static bool model_running = false;

bool init_model(const char *model_path);
static void check_status(OrtStatus *status);
void extract_l1_features(flow_stats_t *flow, float *features);
void extract_l1_features(flow_stats_t *flow, float *input_l1_values);

static void check_status(OrtStatus *status){
    if(status != NULL){
        const char* msg = ort_api->GetErrorMessage(status);
        fprintf(stderr, "ONNX Runtime Error: %s\n", msg);
        ort_api->ReleaseStatus(status);
        exit(1); 
    }
}

bool init_model(const char *model_path){
    OrtStatus *status = NULL;
    ort_api = OrtGetApiBase()->GetApi(ORT_API_VERSION);
    if(!ort_api){
        fprintf(stderr, "Failed to get the ONNX Runtime api \n");
        return false;
    }

    // Log_severity_level, log_id, out
    status = ort_api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "nids-model", &ort_env);
    check_status(status);
    printf("Environment set up successfully\n");
    
    // CreateSessionOptions
    status = ort_api->CreateSessionOptions(&options);
    check_status(status);
    printf("Session options set up successfully\n");

    // Create session -> loading from disk to mem
    status = ort_api->CreateSession(ort_env, model_path,options, &session);
    check_status(status);
    printf("Session created successfully\n");
    // printf("Model path %s", model_path);

    status = ort_api->GetAllocatorWithDefaultOptions(&ort_allocator);
    check_status(status);
    printf("Allocator set up successfully\n");

    status = ort_api->SessionGetInputCount(session , &input_count);
    check_status(status);
    printf("Input count %ld", input_count);
    
    status = ort_api->SessionGetOutputCount(session, &output_count);
    check_status(status);
    printf("Output count %ld", output_count);
    
    input_names = (char**)malloc(sizeof(char*) * input_count);
    printf("Input names allocated succesfully\n");

    for(size_t i = 0; i < input_count; i++){
      status = ort_api->SessionGetInputName(session, i, ort_allocator, &input_names[i]);
      check_status(status);
    }
    printf("Input names charged successfully\n");

    output_names = (char**)malloc(sizeof(char*) * output_count);
    printf("Output names allocated successfully\n");

    for(size_t i = 0; i < output_count; i++){
      status = ort_api->SessionGetOutputName(session, i, ort_allocator, &output_names[i]);
    }
    printf("Output names charged succesfully\n");
    
    model_running = true;
    return true;
}


int classify_flow(flow_stats_t* flow){
    if(!flow){
        fprintf(stderr, "Error null pointer received in classify flow");
        return -1;
    }
   
    
    OrtStatus *status = NULL;
    OrtValue *input_tensor = NULL;
    OrtValue *output_tensor = NULL;
    
    const int64_t input_dims[] = {1, FEATURE_L1_COUNT};
    float input_values[FEATURE_L1_COUNT];
    float *output_values = NULL;

    extract_l1_features(flow, input_values);
    
    status = ort_api->CreateTensorWithDataAsOrtValue(ort_allocator, input_values, sizeof(float) * FEATURE_L1_COUNT,
                                                     input_dims, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &input_tensor);

    status = ort_api->Run(session, NULL, input_names, &input_tensor, input_count, output_names, output_count, &output_tensor);
    check_status(status);

    int prediction = -1;
    status = ort_api->GetTensorMutableData(output_tensor, (void**)&output_values);
   

    if (output_values[0] > output_values[1]) {
        printf("PREDICTION 0\n");
        prediction = 0; // Normal traffic
    } else {
        prediction = 1; // Attack traffic
        printf("PREDICTION 1\n");
    }
    return 1;
}


void extract_l1_features(flow_stats_t *flow, float *input_l1_values){

    int idx = 0;

    input_l1_values[idx++] = (float)flow->total_fwd_packets;
    input_l1_values[idx++] = (float)flow->total_fwd_bytes;
    input_l1_values[idx++] = (float)flow->fwd_packet_len_min;
    input_l1_values[idx++] = (float)flow->flow_bytes_per_sec;
    input_l1_values[idx++] = (float)flow->fwd_psh_flags;
    input_l1_values[idx++] = (float)flow->fwd_urg_flags;
    input_l1_values[idx++] = (float)flow->fwd_packets_per_sec;
    input_l1_values[idx++] = (float)flow->packet_len_min;
    input_l1_values[idx++] = (float)flow->packet_len_max;
    input_l1_values[idx++] = (float)flow->fin_flag_count;
    input_l1_values[idx++] = (float)flow->syn_flag_count;
    input_l1_values[idx++] = (float)flow->rst_flag_count;
    input_l1_values[idx++] = (float)flow->psh_flag_count;
    input_l1_values[idx++] = (float)flow->urg_flag_count;
    input_l1_values[idx++] = (float)flow->cwr_flag_count;
    input_l1_values[idx++] = (float)flow->ece_flag_count;
    input_l1_values[idx++] = (float)flow->down_up_ratio;
    input_l1_values[idx++] = (float)flow->bwd_bulk_rate_avg;
    input_l1_values[idx++] = (float)flow->subflow_fwd_packets;
    input_l1_values[idx++] = (float)flow->subflow_fwd_bytes;
    input_l1_values[idx++] = (float)flow->fwd_init_win_bytes;
    input_l1_values[idx++] = (float)flow->bwd_init_win_bytes;
    input_l1_values[idx++] = (float)flow->fwd_seg_size_min;
    input_l1_values[idx++] = (float)flow->idle_std;
    input_l1_values[idx++] = (float)flow->idle_min;
    input_l1_values[idx++] = flow->serv_http     ? 1.0f : 0.0f; 
    input_l1_values[idx++] = flow->serv_https    ? 1.0f : 0.0f; 
    input_l1_values[idx++] = flow->serv_mqtt     ? 1.0f : 0.0f; 
    input_l1_values[idx++] = flow->serv_other    ? 1.0f : 0.0f; 
    input_l1_values[idx++] = flow->serv_iot_port ? 1.0f : 0.0f; 
    input_l1_values[idx++] = flow->serv_ephimeral ? 1.0f : 0.0f; 
    input_l1_values[idx++] = flow->serv_ssh      ? 1.0f : 0.0f; 



}



