# Makefile for ML-based NIDS IoT Backend

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -std=c11
LDFLAGS += -L$(ONNX_LIB) 

# Directories
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
LIB_DIR = lib

# Source files
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC_FILES))

# Binary name
TARGET = $(BIN_DIR)/nids_backend

# Include directories
INCLUDES = -I$(INC_DIR) -I/usr/local/include -I$(ONNX_INCLUDE) -I$(SRC_DIR) 

# External libraries 
ONNX_INCLUDE = $(LIB_DIR)/onnxruntime/include
ONNX_LIB = $(LIB_DIR)/onnxruntime/lib

# Libraries
LIBS = -lpcap -ljson-c -lonnxruntime -lm


# Operating system detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    CFLAGS += -D_GNU_SOURCE
    LDFLAGS += -Wl,-rpath,'$$ORIGIN/../lib/onnxruntime/lib'
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -Wl,-rpath,@executable_path/../lib/onnxruntime/lib
endif

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(LIB_DIR)

# Linking the final executable
$(TARGET): $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "Build complete: $(TARGET)"

# Compiling object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Installation
install: all
	@mkdir -p /usr/local/bin
	@mkdir -p /usr/local/etc/nids
	@mkdir -p /var/log/nids
	@cp $(TARGET) /usr/local/bin/
	@cp config.json /usr/local/etc/nids/
	@chmod +x /usr/local/bin/nids_backend
	@echo "Installation complete"

# Clean build files
clean:
	rm -rf $(OBJ_DIR)/* $(TARGET)

# Distribution clean
distclean: clean
	rm -rf $(BIN_DIR) $(OBJ_DIR)

# Run the program
run: all
	sudo $(TARGET) --config config.json

# Debug with valgrind for memory leaks
debug: all
	sudo valgrind --leak-check=full --show-leak-kinds=all $(TARGET) --config config.json --interface lo

# Dependencies
depend: $(SRC_FILES)
	@echo "Generating dependencies..."
	@$(CC) $(CFLAGS) $(INCLUDES) -MM $^ | sed 's|^|$(OBJ_DIR)/|' > .depend

# Check for dependencies file
-include .depend

# Build with ASAN (Address Sanitizer)
asan: CFLAGS += -fsanitize=address -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address
asan: all

# Build with Thread Sanitizer
tsan: CFLAGS += -fsanitize=thread -fno-omit-frame-pointer
tsan: LDFLAGS += -fsanitize=thread
tsan: all

# Build with Undefined Behavior Sanitizer
ubsan: CFLAGS += -fsanitize=undefined -fno-omit-frame-pointer
ubsan: LDFLAGS += -fsanitize=undefined
ubsan: all

# Format code with clang-format
format:
	find $(SRC_DIR) $(INC_DIR) -type f -name "*.c" -o -name "*.h" | xargs clang-format -i -style=file

# Static analysis with cppcheck
check:
	cppcheck --enable=all --std=c11 --inconclusive --suppress=missingIncludeSystem $(SRC_DIR) $(INC_DIR)

# Building individual components
packet_sniffer: directories $(OBJ_DIR)/packet_sniffer.o $(OBJ_DIR)/nids_main.o
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS) $(LIBS)

flow_manager: directories $(OBJ_DIR)/flow_feature_extractor.o $(OBJ_DIR)/nids_main.o
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS) $(LIBS)

model_interface: directories $(OBJ_DIR)/model_interface.o $(OBJ_DIR)/nids_main.o
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS) $(LIBS)

alert_system: directories $(OBJ_DIR)/alert_system.o $(OBJ_DIR)/nids_main.o
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS) $(LIBS)

flow_classifier: directories $(OBJ_DIR)/flow_analyser.o $(OBJ_DIR)/nids_main.o
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LDFLAGS) $(LIBS)

# Help target
help:
	@echo "NIDS Backend Makefile"
	@echo "Available targets:"
	@echo "  all        - Build the NIDS backend (default)"
	@echo "  clean      - Remove object files and executable"
	@echo "  distclean  - Remove all generated files and directories"
	@echo "  install    - Install the NIDS backend to the system"
	@echo "  run        - Build and run the NIDS backend"
	@echo "  debug      - Run with valgrind to check for memory leaks"
	@echo "  asan       - Build with Address Sanitizer"
	@echo "  tsan       - Build with Thread Sanitizer"
	@echo "  ubsan      - Build with Undefined Behavior Sanitizer"
	@echo "  format     - Format the code using clang-format"
	@echo "  check      - Static analysis with cppcheck"
	@echo "  depend     - Generate dependencies"
	@echo "  help       - Show this help message"

.PHONY: all clean distclean install run debug depend format check help asan tsan ubsan directories
