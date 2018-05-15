cmake_minimum_required (VERSION 2.8)

cmake_policy(SET CMP0026 OLD)

find_package(Threads REQUIRED)
find_package(NanoMsg REQUIRED)
find_package(Confuse REQUIRED)
find_package(SCTP REQUIRED)
find_package(Event REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/format/src ${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${PB_INCLUDE_DIRS})
include_directories(${EVENT_INCLUDE_DIRS})

configure_file(src/version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/src/version.h)

file(GLOB_RECURSE SRCS src/*.cpp src/*.c)
add_executable (yeti_management ${SRCS})
target_link_libraries(yeti_management
	${CMAKE_THREAD_LIBS_INIT}
	${NanoMsg_LIBRARIES}
	${Confuse_LIBRARIES}
	${SCTP_LIBRARIES}
	${PB_LIBRARIES}
	${EVENT_LIBRARIES})

install(TARGETS yeti_management DESTINATION ${RUNTIME_DIR})

get_property(TARGET_BINS TARGET yeti_management PROPERTY LOCATION)

#file(GLOB_RECURSE TARGET_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h)
file(GLOB_RECURSE TARGET_CFGS ${CMAKE_CURRENT_SOURCE_DIR}/etc/*)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt.in ${CMAKE_CURRENT_BINARY_DIR}/manifest.txt)
