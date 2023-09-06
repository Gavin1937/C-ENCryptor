cmake_minimum_required(VERSION 3.4-3.25)

project(demo)


# set cmake binary output directory to build/bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)


set(SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/demo.c
)


# build C-ENCryptor library as shared or static library (default is shared)
set(CE_BUILD_SHARED_LIBS ON)
# set(CE_BUILD_SHARED_LIBS OFF)


# adding C-ENCryptor library as subdirectory
# since C-ENCryptor library's primary CMakeLists.txt are in our parent directory,
# we need to use some tricks here for that to work
# You should place C-ENCryptor under your primary CMakeLists.txt file
# and you can add this library using:
# add_subdirectory(path/to/C-ENCryptor)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../ ${CMAKE_CURRENT_BINARY_DIR}/C-ENCryptor)

# setup include path for your project
# so you can use #include "C-ENCryptor/ceapi.h"
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)


# compile & linking
add_executable(demo ${SRC})

set_target_properties(C-ENCryptor PROPERTIES LINKER_LANGUAGE C)

target_link_libraries(demo C-ENCryptor)


# we will copy the data directory to where the executable is
# and also create a output folder there so
# we won't get any issue running the demo
file(
    COPY
    "${CMAKE_CURRENT_SOURCE_DIR}/data/"
    DESTINATION
    "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/data/"
)
file(MAKE_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/output/")
