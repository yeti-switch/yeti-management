cmake_minimum_required (VERSION 2.8)

project(yeti-management)

set(CMAKE_CXX_FLAGS "-g -O2 -fPIC -Wformat -Werror=format-security -std=c++11")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-z,relro")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,-z,relro")

cmake_policy(SET CMP0026 OLD)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(CMAKE_INSTALL_PREFIX /usr)
set(RUNTIME_DIR /usr/bin)
set(LIB_DIR /usr/lib)
set(HDRS_DIR /usr/include/yeti)
set(CFG_DIR /etc/yeti)
set(PKGCFG_DIR /usr/lib/pkgconfig)
set(SHARED_DIR /usr/share/yeti)
set(DEF_CFG_DIR /etc/default)
set(SYSLOG_CFG_DIR /etc/rsyslog.d)
set(INIT_DIR /etc/init.d)

option(VERBOSE_LOGGING "Compile with verbose logging (file,lineno,func)" ON)

#get version
if(EXISTS ${CMAKE_SOURCE_DIR}/.git)
        EXECUTE_PROCESS(
                COMMAND "git" "describe" "--tags" "--abbrev=0"
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                OUTPUT_VARIABLE TAG_VERSION
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        MESSAGE(STATUS "got version from git tags: " ${TAG_VERSION})
        STRING(REGEX REPLACE "[-\\.]" ";" TAG_VERSION_LIST ${TAG_VERSION})
else(EXISTS ${CMAKE_SOURCE_DIR}/.git)
        MESSAGE(FATAL_ERROR "git repository required")
endif(EXISTS ${CMAKE_SOURCE_DIR}/.git)

list(GET TAG_VERSION_LIST 0 MAJOR_VERSION)
list(GET TAG_VERSION_LIST 1 MINOR_VERSION)
list(GET TAG_VERSION_LIST 2 PATCH_VERSION)
#LIST(GET TAG_VERSION_LIST 3 BUILD_VERSION)
set(FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION})

if(VERBOSE_LOGGING)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVERBOSE_LOGGING -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
endif(VERBOSE_LOGGING)

#add_subdirectory(third-party)
add_subdirectory(format)
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(tests)

#packaging
include(${CMAKE_SOURCE_DIR}/cmake/pkg_target.cmake)
add_pkg_target(server)
add_pkg_target(client)
add_custom_target(deb DEPENDS server-pkg client-pkg client-dev-pkg)
