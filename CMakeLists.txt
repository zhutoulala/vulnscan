cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

project(vulnscan)

enable_language(C)
enable_language(CXX)

if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    set(CMAKE_CXX_FLAGS         "-Wall -Wno-unknown-pragmas -Wno-sign-compare -Woverloaded-virtual -Wwrite-strings -Wno-unused")
    set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g3")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
endif()


##########################################################################	
# Download and unpack googletest at configure time
#########################################################################
configure_file(CMakeLists.gtest.txt googletest-download/CMakeLists.txt)
execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download" )
execute_process(COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download" )

# Prevent GoogleTest from overriding our compiler/linker options
# when building with Visual Studio
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Add googletest directly to our build. This adds
# the following targets: gtest, gtest_main, gmock
# and gmock_main
add_subdirectory("${CMAKE_BINARY_DIR}/googletest-src"
                 "${CMAKE_BINARY_DIR}/googletest-build")

include_directories(
    ${CMAKE_BINARY_DIR}/googletest-src/googletest/include
)
				 
#########################################################################
# Download and unpack capstone at configure time
#########################################################################
configure_file(CMakeLists.capstone.txt capstone-download/CMakeLists.txt)
execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/capstone-download" )
execute_process(COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/capstone-download" )

# Prevent capstone from overriding our compiler/linker options
# when building with Visual Studio
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Add capstone directly to our build. This adds
# the following targets: capstone
add_subdirectory("${CMAKE_BINARY_DIR}/capstone-src"
                 "${CMAKE_BINARY_DIR}/capstone-build")


#########################################################################
# Build main project				 
#########################################################################				 
include_directories(
    ${PROJECT_SOURCE_DIR}/src
    )
	


add_executable(
    ${PROJECT_NAME}
	src/file_typer.cpp
	src/binary_file.cpp
	src/vuln_report.cpp
	src/vulnerability.cpp
	src/vulnscan.cpp
    )

target_link_libraries(
    ${PROJECT_NAME}
    capstone-static
    )				 

add_executable(
    unit_tests
	src/binary_file.cpp
	src/file_typer.cpp
	src/vuln_report.cpp
	src/vulnerability.cpp
    test/main.cpp
    test/test_binary_file.cpp
    test/test_file_typer.cpp
    )

target_link_libraries(
    unit_tests
    gtest
    )

include(CTest)
enable_testing()

add_test(unit ${PROJECT_BINARY_DIR}/unit_tests)
