cmake_minimum_required (VERSION 2.8)

cmake_policy(SET CMP0026 OLD)

find_package(NanoMsg REQUIRED)

include_directories(${PB_INCLUDE_DIRS})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

configure_file(libyeticc.pc.in libyeticc.pc)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libyeticc.pc DESTINATION ${PKGCFG_DIR})

install(FILES FindYetiCC.cmake DESTINATION ${SHARED_DIR})

add_library(yeticc SHARED src/yeticc.cpp)
set_target_properties(yeticc PROPERTIES
	VERSION ${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}
	SOVERSION ${MAJOR_VERSION})
target_link_libraries(yeticc
	${PB_LIBRARIES}
	${NanoMsg_LIBRARIES})

install(TARGETS yeticc DESTINATION ${LIB_DIR})

get_property(TARGET_LIBS TARGET yeticc PROPERTY LOCATION)

file(GLOB_RECURSE TARGET_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h)
file(GLOB_RECURSE TARGET_PKGCFGS ${CMAKE_CURRENT_BINARY_DIR}/*.pc)
file(GLOB_RECURSE TARGET_CMAKE_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/*.cmake)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt.in ${CMAKE_CURRENT_BINARY_DIR}/manifest.txt)
