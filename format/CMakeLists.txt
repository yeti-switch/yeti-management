cmake_minimum_required (VERSION 2.8)

find_package(Protobuf REQUIRED)

file(GLOB_RECURSE PB_DEFS defs/*.proto)

message(STATUS "Generate protocol buffers classes")
execute_process(
	COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR}/defs --cpp_out ${CMAKE_CURRENT_BINARY_DIR} ${PB_DEFS}
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	RESULT_VARIABLE PROTOC_RESULT
	ERROR_VARIABLE PROTOC_ERROR
	OUTPUT_VARIABLE PROTOC_OUTPUT)
if(PROTOC_RESULT)
	message(FATAL_ERROR "can't generate procotol buffers classes: ${PROTOC_ERROR}")	
endif(PROTOC_RESULT)

foreach(def ${PB_DEFS})
	get_filename_component(src ${def} NAME_WE)
	list(APPEND PB_LIBS ${CMAKE_CURRENT_BINARY_DIR}/${src}.pb.cc)
endforeach(def)

add_library(pb_classes ${PB_LIBS})

set(PB_LIBRARIES pb_classes ${PROTOBUF_LIBRARIES} PARENT_SCOPE)
set(PB_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR} ${PROTOBUF_INCLUDE_DIRS} PARENT_SCOPE)
