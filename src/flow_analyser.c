#include "onnxruntime_c_api.h"
#include <stdio.h>
#include "nids_backend.h"


static const OrtApi *ort_api = NULL;


static OrtEnv *ort_env = NULL;
static OrtSessionOptions *options = NULL;
static OrtSession *session = NULL;
static OrtAllocator *ort_allocator = NULL;
static size_t input_count = 0;
OrtValue *output_tensor = NULL;

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
    printf("Ort api %p\n", ort_api);
    
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
    printf("Model path %s", *model_path);
    status = ort_api->SessionGetInputCount(session , &input_count);
    printf("Input count %ld", input_count);

    return true;
}
