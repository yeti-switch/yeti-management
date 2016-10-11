cmake_minimum_required (VERSION 2.8)

add_executable (ask_config ask_config.cpp)
target_link_libraries(ask_config yeticc) 

include_directories(${CMAKE_SOURCE_DIR}/client/src/)
