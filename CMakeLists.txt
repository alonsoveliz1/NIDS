cmake_minimum_required (VERSION 3.28.3)
project (nids_backend VERSION 0.1 LANGUAGES C)

# --------------------------------------------------------------------
#  Build options and defaults
# --------------------------------------------------------------------
option (ENABLE_SANITISERS "Compile with Address/Thread/UB sanitisers" OFF)

set (CMAKE_C_STANDARD 11)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_POSITION_INDEPENDENT_CODE ON)        

# Put everything produced by the build in one place:
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Helpful compile defs
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_compile_definitions (_GNU_SOURCE)
endif ()

# --------------------------------------------------------------------
#  1.  Core static library – code shared by backend & unit tests
# --------------------------------------------------------------------
set (NIDS_CORE_SRC
    src/flow_analyser.c
    src/flow_feature_extractor.c
    src/packet_queue.c
    src/sniffer.c
    src/config.c
    src/log.c
)

set(CMAKE_INSTALL_RPATH "$ORIGIN/../../lib/onnxruntime/lib")
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)


add_library (nids_core STATIC ${NIDS_CORE_SRC})
target_include_directories (nids_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${ONNXRUNTIME_INCLUDE_DIR}
)

# --------------------------------------------------------------------
#  2.  Third-party libraries
# --------------------------------------------------------------------
find_package (PkgConfig REQUIRED)

pkg_check_modules (PCAP   REQUIRED IMPORTED_TARGET libpcap)
pkg_check_modules (JSONC  REQUIRED IMPORTED_TARGET json-c)
pkg_check_modules (CRITERION REQUIRED IMPORTED_TARGET criterion)  

# ---- ONNX Runtime: vendored bundle or system install --------------
set(ONNX_DEFAULT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib/onnxruntime)

find_path (ONNXRUNTIME_INCLUDE_DIR 
           NAMES onnxruntime_c_api.h
           HINTS ${ONNXRUNTIME_ROOT} ENV ONNXRUNTIME_ROOT ${ONNX_DEFAULT_PATH}
           PATH_SUFFIXES include)

find_library (ONNXRUNTIME_LIBRARY 
              NAMES onnxruntime
              HINTS ${ONNXRUNTIME_ROOT} ENV ONNXRUNTIME_ROOT ${ONNX_DEFAULT_PATH}
              PATH_SUFFIXES lib)

add_library (onnxruntime::onnxruntime UNKNOWN IMPORTED)

set_target_properties (onnxruntime::onnxruntime PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ONNXRUNTIME_INCLUDE_DIR}"
    IMPORTED_LOCATION             "${ONNXRUNTIME_LIBRARY}"
)

# --------------------------------------------------------------------
#  3.  Production executable
# --------------------------------------------------------------------
add_executable (nids_backend src/nids_main.c)

target_include_directories (nids_backend PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries (nids_backend PRIVATE
    nids_core
    PkgConfig::PCAP
    PkgConfig::JSONC
    onnxruntime::onnxruntime
    m
)

# RPATH so the executable can find libonnxruntime next to itself
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options (nids_backend PRIVATE
        "LINKER:-rpath,$ORIGIN/../lib/onnxruntime/lib")
endif ()

# Optional sanitiser flags
if (ENABLE_SANITISERS)
    foreach (t nids_core nids_backend)
        target_compile_options (${t} PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer)
        target_link_options   (${t} PRIVATE
            -fsanitize=address,undefined)
    endforeach ()
endif ()

# --------------------------------------------------------------------
#  4.  Installation
# --------------------------------------------------------------------
include (GNUInstallDirs)
install (TARGETS nids_backend DESTINATION ${CMAKE_INSTALL_BINDIR})

# --------------------------------------------------------------------
#  5.  Unit-test executable (Criterion)
# --------------------------------------------------------------------
enable_testing ()

file (GLOB TEST_SRC CONFIGURE_DEPENDS tests/*.c)

add_executable (nids_unit_tests ${TEST_SRC})

target_include_directories (nids_unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries (nids_unit_tests PRIVATE
    nids_core
    PkgConfig::CRITERION
    onnxruntime::onnxruntime
)

add_test (NAME unit_tests COMMAND nids_unit_tests)

