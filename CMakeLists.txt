cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

project(vulnscan)

enable_language(C)
enable_language(CXX)

if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    set(CMAKE_CXX_FLAGS         "-std=c++11 -Wall -Wno-unknown-pragmas -Wno-sign-compare -Woverloaded-virtual -Wwrite-strings -Wno-unused")
    set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g3")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
endif()


##########################################################################	
# Download and unpack googletest at configure time
#########################################################################
configure_file(dependencies/CMakeLists.gtest.txt googletest-download/CMakeLists.txt)
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
configure_file(dependencies/CMakeLists.capstone.txt capstone-download/CMakeLists.txt)
execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/capstone-download" )
execute_process(COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/capstone-download" )


# Add capstone directly to our build. This adds
# the following targets: capstone
add_subdirectory("${CMAKE_BINARY_DIR}/capstone-src"
                 "${CMAKE_BINARY_DIR}/capstone-build")

include_directories(
    ${CMAKE_BINARY_DIR}/capstone-src/include
)

#########################################################################
# Download and unpack pe-parse at configure time
#########################################################################
configure_file(dependencies/CMakeLists.peparse.txt pe-parse-download/CMakeLists.txt)
execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/pe-parse-download" )
execute_process(COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/pe-parse-download" )

# Add pe-parse directly to our build. This adds
# the following targets: pe-parse
add_subdirectory("${CMAKE_BINARY_DIR}/pe-parse-src"
                 "${CMAKE_BINARY_DIR}/pe-parse-build")

include_directories(
    ${CMAKE_BINARY_DIR}/pe-parse-src/pe-parser-library/include
)

#########################################################################
# other dependencies
#########################################################################

add_subdirectory(dependencies/strings2)

include_directories(
    ${PROJECT_SOURCE_DIR}/dependencies/strings2/strings
)



#########################################################################
# Build main project				 
#########################################################################				 
include_directories(
    ${PROJECT_SOURCE_DIR}/src
    )
	


add_executable(
    ${PROJECT_NAME}
	src/file_typer.cpp
	src/windows_binary.cpp
	src/linux_binary.cpp
	src/vuln_report.cpp
	src/vulnerability.cpp
	src/vulnscan.cpp
	src/disassembler.cpp
	src/signature.cpp
	src/windows_symbols.cpp
	src/asm_scanner.cpp
	src/string_scanner.cpp
	src/scan_engine.cpp
    )

target_link_libraries(
    ${PROJECT_NAME}
    capstone-static
	pe-parser-library
	strings2
    )				 

add_executable(
    unit_tests
	src/windows_binary.cpp
	src/linux_binary.cpp
	src/file_typer.cpp
	src/vuln_report.cpp
	src/vulnerability.cpp
	src/disassembler.cpp
	src/signature.cpp	
	test/main.cpp	
	test/test_windows_binary.cpp
	test/test_file_typer.cpp
	test/test_disassembler.cpp
	test/test_signature.cpp
	test/test_vulnerability.cpp
    )

target_link_libraries(
	unit_tests
	gtest
	capstone-static
	pe-parser-library
	strings2
    )


include(CTest)
enable_testing()

add_test(unit ${PROJECT_BINARY_DIR}/unit_tests)
