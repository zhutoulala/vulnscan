cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

project(strings2)

enable_language(C)
enable_language(CXX)

if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    set(CMAKE_CXX_FLAGS         "-std=c++11 -Wall -Wno-unknown-pragmas -Wno-sign-compare -Woverloaded-virtual -Wwrite-strings -Wno-unused")
    set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g3")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
endif()


#########################################################################
# Build main project				 
#########################################################################				 
include_directories(
    ${PROJECT_SOURCE_DIR}/strings
    )
	

add_library(
    ${PROJECT_NAME}
	strings/print_buffer.cpp
	strings/string_parser.cpp
    )