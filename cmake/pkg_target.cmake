MACRO(ADD_PKG_TARGET target)
	set(ROOT_DIR ${CMAKE_SOURCE_DIR})
	set(BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/packages/${target})

	include(${PROJECT_BINARY_DIR}/${target}/manifest.txt)

	IF(EXISTS ${CMAKE_SOURCE_DIR}/packages/package-${target}-dev.txt)
		set(HAVE_DEV_PACKAGE True)
		set(BUILD_DIR_DEV ${CMAKE_CURRENT_BINARY_DIR}/packages/${target}-dev)
		configure_file(packages/package-${target}-dev.txt ${BUILD_DIR_DEV}/CMakeLists.txt @ONLY)
		configure_file(packages/common-dev.txt.in ${BUILD_DIR_DEV}/common-dev.txt @ONLY)
	ENDIF(EXISTS ${CMAKE_SOURCE_DIR}/packages/package-${target}-dev.txt)

	configure_file(packages/package-${target}.txt ${BUILD_DIR}/CMakeLists.txt @ONLY)
	configure_file(packages/common.txt.in ${BUILD_DIR}/common.txt @ONLY)

	#copy all files from folders like "packages/${target} (used for extra control files)
	if(EXISTS ${CMAKE_SOURCE_DIR}/packages/${target})
		file(GLOB EXTRA_FILES packages/${target}/*)
		foreach(extra_file ${EXTRA_FILES})
			file(COPY ${extra_file} DESTINATION ${BUILD_DIR})
		endforeach(extra_file)
	endif(EXISTS ${CMAKE_SOURCE_DIR}/packages/${target})

	add_custom_target(${target}-pkg
		COMMAND ${CMAKE_COMMAND} . 
		COMMAND ${CMAKE_CPACK_COMMAND} -G DEB
		COMMAND cp *.deb ${PROJECT_BINARY_DIR}
		WORKING_DIRECTORY ${BUILD_DIR}
	)

	#add dev package target
	if(HAVE_DEV_PACKAGE)
		if(EXISTS ${CMAKE_SOURCE_DIR}/packages/${target}-dev)
			file(GLOB EXTRA_FILES packages/${target}-dev/*)
			foreach(extra_file ${EXTRA_FILES})
				file(COPY ${extra_file} DESTINATION ${BUILD_DIR})
			endforeach(extra_file)
		endif(EXISTS ${CMAKE_SOURCE_DIR}/packages/${target}-dev)

		add_custom_target(${target}-dev-pkg
			COMMAND ${CMAKE_COMMAND} . 
			COMMAND ${CMAKE_CPACK_COMMAND} -G DEB
			COMMAND cp *.deb ${PROJECT_BINARY_DIR}
			WORKING_DIRECTORY ${BUILD_DIR_DEV}
		)
	endif(HAVE_DEV_PACKAGE)

ENDMACRO(ADD_PKG_TARGET target)
