cmake_minimum_required(VERSION 2.8)

#Include configuration file
include( configuration.cmake)

#Include generic_modules
include( generic_modules.cmake)

#Import libraries in IMPORTED LIBRARIES
foreach ( import_lib ${IMPORTED_LIBRARIES})

	add_library( ${import_lib} STATIC IMPORTED)
	set_target_properties( ${import_lib} PROPERTIES IMPORTED_LOCATION ${${import_lib}_IMPORTED_LOCATION})

endforeach()

#Add the target of all libraries
macro_register_target_list( STATIC_LIBRARIES)

#Add the target of all executables
macro_register_target_list( EXECUTABLES)

foreach( lib ${EXECUTABLE};${STATIC_LIBRARIES})
    add_dependencies( ${lib} test_prepare)
endforeach()
