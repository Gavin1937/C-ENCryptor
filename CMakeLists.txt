cmake_minimum_required(VERSION 3.4-3.25)

project(C-ENCryptor LANGUAGES C)


# src files
file(GLOB SRC
    "src/*.c"
)
file(GLOB HEADER
    "include/*.h"
)


# setup external libraries

# openssl
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
message("-- Found OPENSSL_VERSION: ${OPENSSL_VERSION}")
if (OPENSSL_VERSION VERSION_GREATER_EQUAL 3)
    set(CE_OSSL_COMPATIBLE_MODE OFF)
else()
    set(CE_OSSL_COMPATIBLE_MODE ON)
endif()


# zlib
add_subdirectory(${PROJECT_SOURCE_DIR}/vendor/zlib EXCLUDE_FROM_ALL ${CMAKE_CURRENT_BINARY_DIR}/zlib-build)
include_directories(${PROJECT_SOURCE_DIR}/vendor)


# handle build options

# CE_BUILD_SHARED_LIBS
option(CE_BUILD_SHARED_LIBS "Build C-ENCryptor as Shared Library" ON)
if (CE_BUILD_SHARED_LIBS)
    set(CE_BUILD_TYPE SHARED)
else()
    set(CE_BUILD_TYPE STATIC)
endif()

# CE_OSSL_COMPATIBLE_MODE
option(CE_OSSL_COMPATIBLE_MODE "Turn OpenSSL3 Backward Compatibility Mode ON/OFF" OFF)
if (CE_OSSL_COMPATIBLE_MODE)
    add_definitions(-DCE_OSSL_COMPATIBLE_MODE)
endif()

# report
message("-- Build Options:")
message("-- CE_BUILD_SHARED_LIBS: ${CE_BUILD_SHARED_LIBS}")
message("-- CE_OSSL_COMPATIBLE_MODE: ${CE_OSSL_COMPATIBLE_MODE}")
message("-- CMAKE_CONFIGURATION_TYPES: ${CMAKE_CONFIGURATION_TYPES}")
message("-- CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")


# build library
add_library(${PROJECT_NAME} ${CE_BUILD_TYPE}
    ${SRC}
    ${HEADER}
)
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C)

# linking

target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

target_link_libraries(${PROJECT_NAME} zlibstatic)
# add -fPIC compile flag for zlib in linux system
set_property(TARGET zlibstatic PROPERTY POSITION_INDEPENDENT_CODE ON)
# when CMake configures zlib, it will rename "zlib/zconf.h" to "zlib/zconf.h.included"
# this will break our program when compiling with #include <zlib/zlib.h>
# following function will rename the file back to its original name
# checkout this github issue for detail:
# https://github.com/grpc/grpc/issues/11581#issuecomment-356267921
file(
    RENAME
    "${PROJECT_SOURCE_DIR}/vendor/zlib/zconf.h.included"
    "${PROJECT_SOURCE_DIR}/vendor/zlib/zconf.h"
)
message("-- Renaming \"zconf.h.included\" back to \"zconf.h\"")

