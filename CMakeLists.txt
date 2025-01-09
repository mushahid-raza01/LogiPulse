cmake_minimum_required(VERSION 3.15)

# Project name
project(MonitoringLibrary LANGUAGES CXX)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define the output as a DLL (shared library)
add_library(${PROJECT_NAME} SHARED)

# Specify the Boost root directory
if(NOT DEFINED BOOST_ROOT)
    set (BOOST_ROOT "E:\\OrderExecServer\\Libraries_64bit_VC17\\boost_1_82_0")
endif()

IF (WIN32)
    SET(Boost_NAMESPACE ${Boost_NAMESPACE} "libboost")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc")
ENDIF()
# Define UNICODE for wide string usage
add_definitions(-DUNICODE -D_UNICODE)

set(CMAKE_BUILD_TYPE Release)

# Include Boost headers

# Add your source files here
# Replace with your actual source files
set(SOURCES
    MonitoringLibrary.cpp
)

# Link Boost libraries (replace COMPONENTS with your required Boost libraries)
# Example: COMPONENTS filesystem system
find_package(Boost REQUIRED COMPONENTS json chrono)

include_directories(${Boost_INCLUDE_DIRS})

target_sources(${PROJECT_NAME} PRIVATE ${SOURCES})

# Link Boost to the library
target_link_libraries(${PROJECT_NAME} PUBLIC ${Boost_LIBRARIES})

# Specify the output directory for the DLL
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# Add an installation target for the DLL
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
