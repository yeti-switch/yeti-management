#.rst:
# FindNanoMsg
# --------
#
# Find NanoMsg
#
# Find NanoMsg headers and libraries.
#
# ::
#
#   NanoMsg_LIBRARIES      - List of libraries when using NanoMsg.
#   NanoMsg_FOUND          - True if libnanomsg found.
#   NanoMsg_VERSION        - Version of found libnanomsg.

find_package(PkgConfig REQUIRED)
pkg_check_modules(NanoMsg libnanomsg)

# handle the QUIETLY and REQUIRED arguments and set NanoMsg_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(NanoMsg
                                  REQUIRED_VARS NanoMsg_LIBRARIES
				  VERSION_VAR NanoMsg_VERSION)

