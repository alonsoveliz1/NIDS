#include "onnxruntime_c_api.h"
#include <stdio.h>
#include "nids_backend.h"
#include <string.h>


static const OrtApi *ort_api = NULL;
static OrtEnv *ort_env = NULL;
static OrtSessionOptions *options = NULL;
static OrtSession *session = NULL;
static OrtAllocator *ort_allocator = NULL;
static size_t input_count = 0;
static size_t output_count = 0;
static char **input_names = NULL;
static char **output_names = NULL;

static model_running = false;

bool init_model(const char *model_path);
static void check_status(OrtStatus *status);

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

    for(int i = 0; i < input_count; i++){
      status = ort_api->SessionGetInputName(session, i, ort_allocator, &input_names[i]);
      check_status(status);
    }
    printf("Input names charged successfully\n");

    output_names = (char**)malloc(sizeof(char*) * output_count);
    printf("Output names allocated successfully\n");

    for(int i = 0; i < output_count; i++){
      status = ort_api->SessionGetOutputName(session, i, ort_allocator, &output_names[i]);
    }
    printf("Output names charged succesfully\n");
    
    model_running = true;
    return true;
}


int classify_flow(flow_stats_t* flow){
    float *output_values = NULL;

    // Necesito un array con los atributos para pasarselo como input_values
    input_values = [34]
    // Completar el array

    ort_api->Run(session, options, input_names, input_values, input_count, output_names, output_count, &output_tensor);

    output_values = [2]
    // Confidence / prediction?
    output_values = ort_api->GetTensorMutableData(output_tensor, output_values, 2);

}


