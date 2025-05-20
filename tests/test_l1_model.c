#include <stdio.h>
#include <string.h>
#include "nids_backend.h"
#include <criterion/criterion.h>

#define MAX_LINE_LEN 1024
#define TEST_COUNT 100
#define FEATURES_L1_DATASET 100

int test_l1_model(FILE *fp, char *line);
int find_column_index(char *header, const char *col_name);
void get_parsed_attributes(char *features, float *parsed_features, int *indices);
int get_correct_label(char* features, int col_label);

Test(nids_model, test_l1_predictions_on_csv){
    config = malloc(sizeof(nids_config_t));
    config->model_path = strdup("../../xgboost_model.onnx");

    if(!(initialize_model() != 0)){
        fprintf(stderr, "ONNX Model could not be initialized properly");
    }

    FILE *fp = fopen("combinado_balanceado.csv", "r");
    if(!fp){
        perror("Unable to open file");
    }

    char line[MAX_LINE_LEN];
    if(!fgets(line, sizeof(line), fp)){
        perror("Failed to read the header");
        fclose(fp);
    }
    test_l1_model(fp, line);
}


int test_l1_model(FILE *fp, char *line){

    const char* target_features_l1[] = {
      "Total Length of Fwd Packet",
      "Fwd Packet Length Min",
      "Bwd Packet Length Min",
      "Flow Bytes/s",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Fwd PSH Flags",
      "Fwd URG Flags",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Packet Length Min",
      "Packet Length Max",
      "FIN Flag Count",
      "SYN Flag Count",
      "RST Flag Count",
      "PSH Flag Count",
      "URG Flag Count",
      "CWR Flag Count",
      "ECE Flag Count",
      "Down/Up Ratio",
      "Bwd Bulk Rate Avg",
      "Subflow Fwd Packets",
      "Subflow Fwd Bytes",
      "FWD Init Win Bytes",
      "Bwd Init Win Bytes",
      "Fwd Seg Size Min",
      "Active Mean",
      "Active Std",
      "Idle Std",
      "Idle Min",
      "Service_http",
      "Service_https",
      "Service_mqtt",
      "Service_other",
      "Service_iot_port",
      "Service_ephimeral",
      "Service_ssh"
  };

    int indices[FEATURE_L1_COUNT];

    for(int i = 0; i < FEATURE_L1_COUNT; i++){
        indices[i] = find_column_index(line, target_features_l1[i]);
        if(indices[i] == -1){
            printf("Feature %s could not be founc in CSV header. \n", target_features_l1[i]);
            fclose(fp);
            return 1;
        }
    }
    
    const char *label = "Label";
    int col_label = find_column_index(line, label);

    for(int i = 0; i < TEST_COUNT; i++){
        char features[MAX_LINE_LEN];
        float parsed_features[FEATURE_L1_COUNT];
        if(!fgets(features, MAX_LINE_LEN, fp)){
            perror("Failed to read the file");
            fclose(fp);
            return 1;
        }
        get_parsed_attributes(features, parsed_features, indices);

        int prediction = test_classify_flow(parsed_features);
        int correct_label = get_correct_label(features, col_label);

        cr_assert_eq(prediction, correct_label);
    }
    return 0;
}


int find_column_index(char *header, const char *col_name){
    char *token;
    int index = 0;
    char *header_copy = strdup(header);
    token = strtok(header_copy, ",");

    while(token != NULL){
        if(strcmp(token, col_name) == 0){
            free(header_copy);
            return index;
        }
        token = strtok(NULL, ",");
        index++;
    }
    free(header_copy);
    return -1;
}


/* Indexes are ordered in ascending order */
void get_parsed_attributes(char *features, float *parsed_features, int *indexes){
    char *token;
    int index = 0;
    int i = 0;
    char *features_copy = strdup(features);
    token = strtok(features_copy, ",");

    while(token != NULL){
        if(indexes[i] == index){
            parsed_features[i] = strtof(token, NULL);
            i++;
        }
        token = strtok(NULL, ",");
        index++;
    }
    free(features_copy);
}


int get_correct_label(char* features, int col_label){
    char *token;
    char *end;
    int i = 0;
    char *features_copy = strdup(features);
    token = strtok(features_copy, ",");

    while(token != NULL){
        if(i == col_label){
            return strtol(token, &end, 0);
        }
        i++;
        token = strtok(NULL, ",");
    }
    free(features_copy);
    return -1;
}



