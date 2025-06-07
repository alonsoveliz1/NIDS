#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nids_backend.h"
#include <criterion/criterion.h>

#define MAX_LINE_LEN 4098
#define FEATURES 89

typedef struct{
	char *feature;
	int pos;
} featurePosMap_t;

static FILE *test_csv;
static char line[MAX_LINE_LEN];

featurePosMap_t feature_map[FEATURES];		// Array with all the features and their respective positions on the test csv [0..88]
int pos_features_csv[FEATURE_L1_COUNT];		// Array with the positions of the features model needs in order [0..67]
int pos_label;				 	// Position of the label in the test csv

int test_l1_model(float *test_i, int label_i, int row_num, int *mismatch_count);
int find_column_index(char *header, const char *col_name);
void get_parsed_attributes(char *features, float *parsed_features, int *indices);
int get_correct_label(char* features, int col_label);
int extract_features(char *line, float *test_i, int *label_i);
void parse_csv_header(void);
void cleanup_test(void);
void setup_test(void);

TestSuite(nids_model, .init = setup_test, .fini = cleanup_test);

Test(nids_model, test_l1_predictions_on_csv){
		
	float test_i[FEATURE_L1_COUNT];
	int label_i;
	int row_count = 0;
	int mismatch_count = 0;
	
	while(fgets(line, sizeof(line), test_csv)){
		row_count++;
		extract_features(line, test_i, &label_i);
		test_l1_model(test_i, label_i, row_count, &mismatch_count);
	}
	
	
	// Summary
	printf("\n========== TEST SUMMARY ==========\n");
	printf("Total rows tested: %d\n", row_count);
	printf("Mismatches: %d\n", mismatch_count);
	printf("Accuracy: %.2f%%\n", ((row_count - mismatch_count) * 100.0) / row_count);
	printf("==================================\n");
	
	// Fail the test if there were any mismatches
	cr_assert_eq(mismatch_count, 0, "Found %d prediction mismatches out of %d rows", mismatch_count, row_count);
}	


int extract_features(char *line, float *test_i, int *label_i) {
	int col = 0;
	char *tok = strtok(line, ",");
	while (tok != NULL) {
		for (int i = 0; i < FEATURE_L1_COUNT; i++) {
			if (pos_features_csv[i] == col) {
				test_i[i] = strtof(tok, NULL);  // Convert string to float
        		}
		}
		if (col == pos_label) {
			*label_i = atoi(tok);  // Convert string to int
		}
		tok = strtok(NULL, ",");
		col++;
	}
	return NIDS_OK;
}



int test_l1_model(float *test_i, int label_i, int row_num, int *mismatch_count){
        int prediction = test_classify_flow(test_i);
	// printf("\nRow %d - PREDICTION: %d | LABEL: %d", row_num, prediction, label_i);
	
	if (prediction != label_i) {
		// printf(" [MISMATCH!]\n");
		(*mismatch_count)++;
	}	
    	return NIDS_OK;
}



void parse_csv_header(void){
		test_csv = fopen("../tests/balanced_test_total.csv", "r");
		if(!test_csv){
			perror("Unable to open file");
		}

		if(!fgets(line, sizeof(line), test_csv)){
			perror("Failed to read the header");
			fclose(test_csv);
		}

		int pos = 0;
		char *tok;
		tok = strtok(line, ",");
		while(tok != NULL){
			feature_map[pos].feature = strdup(tok);
			feature_map[pos].pos = pos;
			printf("Pos %d, attribute : %s\n",pos, tok);
			pos++;
			tok = strtok(NULL,",");
		}
		const char* feature_names[] = {
		    "Flow Duration",                    // 0
		    "Total Length of Fwd Packet",       // 1
		    "Total Length of Bwd Packet",       // 2
		    "Fwd Packet Length Min",            // 3
		    "Fwd Packet Length Std",            // 4
		    "Bwd Packet Length Max",            // 5
		    "Bwd Packet Length Min",            // 6
		    "Flow Bytes/s",                     // 7
		    "Flow Packets/s",                   // 8
		    "Flow IAT Mean",                    // 9
		    "Flow IAT Std",                     // 10
		    "Fwd IAT Total",                    // 11
		    "Fwd IAT Mean",                     // 12
		    "Fwd IAT Std",                      // 13
		    "Fwd IAT Max",                      // 14
		    "Fwd IAT Min",                      // 15
		    "Bwd IAT Total",                    // 16
		    "Bwd IAT Mean",                     // 17
		    "Bwd IAT Std",                      // 18
		    "Bwd IAT Max",                      // 19
		    "Fwd PSH Flags",                    // 20
		    "Fwd URG Flags",                    // 21
		    "Fwd Header Length",                // 22
		    "Bwd Header Length",                // 23
		    "Bwd Packets/s",                    // 24
		    "Packet Length Min",                // 25
		    "Packet Length Max",                // 26
		    "Packet Length Mean",               // 27
		    "FIN Flag Count",                   // 28
		    "SYN Flag Count",                   // 29
		    "RST Flag Count",                   // 30
		    "PSH Flag Count",                   // 31
		    "ACK Flag Count",                   // 32
		    "URG Flag Count",                   // 33
		    "CWR Flag Count",                   // 34
		    "ECE Flag Count",                   // 35
		    "Down/Up Ratio",                    // 36
		    "Bwd Segment Size Avg",             // 37
		    "Bwd Bytes/Bulk Avg",               // 38
		    "Bwd Packet/Bulk Avg",              // 39
		    "Bwd Bulk Rate Avg",                // 40
		    "Subflow Fwd Packets",              // 41
		    "Subflow Fwd Bytes",                // 42
		    "Subflow Bwd Packets",              // 43
		    "Subflow Bwd Bytes",                // 44
		    "FWD Init Win Bytes",               // 45
		    "Bwd Init Win Bytes",               // 46
		    "Fwd Act Data Pkts",                // 47
		    "Fwd Seg Size Min",                 // 48
		    "Active Mean",                      // 49
		    "Active Std",                       // 50
		    "Idle Std",                         // 51
		    "Idle Min",                         // 52
		    "Service_CustomService/IRC-Alt",    // 53
		    "Service_Ephemeral",                // 54
		    "Service_HTTP",                     // 55
		    "Service_HTTP-Alt",                 // 56
		    "Service_HTTPS",                    // 57
		    "Service_IRC",                      // 58
		    "Service_IoT",                      // 59
		    "Service_IoT-Gateway",              // 60
		    "Service_MQTT",                     // 61
		    "Service_Other",                    // 62
		    "Service_RTSP",                     // 63
		    "Service_RemoteShell/CustomApp",    // 64
		    "Service_SSH",                      // 65
		    "Service_Telnet",                   // 66
		    "Service_UnknownApp"                // 67
		};


		// Check if all expected features were matched
		for (int i = 0; i < FEATURE_L1_COUNT; i++) {
		    int matched = 0;
		    for (int j = 0; j < FEATURES; j++) {
			if (strcmp(feature_names[i], feature_map[j].feature) == 0) {
				pos_features_csv[i] = j;
				matched = 1;
				break;
			}

			if(strcmp(feature_names[i], "Service_RemoteShell/CustomApp") == 0){
				pos_features_csv[i] = 88;
				matched = 1;
				break;

			}
		    }
		    if (!matched) {
			printf("Feature not matched: \"%s\"\n", feature_names[i]);
		    }
		}


		for(int i = 0; i < FEATURES; i++){
			if(strcmp(feature_map[i].feature, "Label") == 0){
				pos_label = i;
				break;
			}
		}
}



void setup_test(void){
	config = malloc(sizeof(nids_config_t));
	config->model_path = strdup("../xgboost_model.onnx");

	cr_assert_eq(init_model(), 0, "ONNX Model could not be initialized properly");


	parse_csv_header();
}



void cleanup_test(void){
	if(test_csv){
		fclose(test_csv);
	}

	stop_model();

	for(int i = 0; i < FEATURES; i++){
		free(feature_map[i].feature);
		feature_map[i].feature = NULL;
	}

	if(config){
		free(config->model_path);
		free(config);
	}
}
