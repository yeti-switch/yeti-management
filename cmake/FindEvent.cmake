#.rst:
# FindEvent
# --------
#
# Find Event
#
# Find libevent headers and libraries.
#
# ::
#
#   EVENT_LIBRARIES      - List of libraries when using libevent.
#   EVENT_FOUND          - True if libevent found.
#   EVENT_VERSION        - Version of found libevent

find_package(PkgConfig REQUIRED)
pkg_check_modules(EVENT libevent)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
    EVENT
    REQUIRED_VARS EVENT_LIBRARIES
    VERSION_VAR EVENT_VERSION)

