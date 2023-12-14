#Set the [property] of a [target] defined in configuration file or inherit this [property] from [target_list]
macro( macro_set_or_inherit_property target_list target property)

    if ( ${target}_${property})

        #Set the property of this target
        set_target_properties( ${target} PROPERTIES ${property} ${${target}_${property}})

    elseif( ${target_list}_${property})

        #Inherit the property from his target_list
        set_target_properties( ${target} PROPERTIES ${property} ${${target_list}_${property}})

    endif()

endmacro()

#Get all source files of the [target] according to the member of _SOURCE_DIRECTORY _FILE_LIST _FILE_LIST_EXCLUDE
#then store the result in the member of _SOURCE.
#If source files are located in different directories we can also set the member of _SOURCE directly
macro( macro_get_source target)
	
	#Source is specified in configuration.txt directly
	if ( ${target}_SOURCE)

	#Include files in _FILE_LIST located in _SOURCE_DIRECTORY
	elseif( ${target}_FILE_LIST AND ${target}_SOURCE_DIRECTORY)

		set( ${target}_SOURCE "")
		foreach( file ${${target}_FILE_LIST})
			list( APPEND ${target}_SOURCE ${${target}_SOURCE_DIRECTORY}/${file})
		endforeach()

	#Include all files in _SOURCE_DIRECTORY and exclude all files in _FILE_LIST_EXCLUDE
	elseif( ${target}_SOURCE_DIRECTORY)

		aux_source_directory( ${${target}_SOURCE_DIRECTORY} ${target}_SOURCE)
		if ( ${target}_FILE_EXCLUDE_LIST)

			foreach ( src_file ${${target}_SOURCE})
				foreach ( exclude_file ${${target}_FILE_EXCLUDE_LIST})
					if ( ${src_file} MATCHES ${exclude_file})
						list( REMOVE_ITEM ${target}_SOURCE ${src_file})
					endif()
				endforeach()
			endforeach()

		endif()

	endif()

	#If the member of _SOURCE_DIRECTORY is not defined, we must set the member of _SOURCE directly

endmacro()

#Add the [target] in [target_list], we must call different cmake functions according to [target_list]
macro( macro_create_target target_list target)

	#Call add_library while adding a STATIC_LIBRARIES target
	if ( ${target_list} STREQUAL STATIC_LIBRARIES)

		if ( ${target}_SOURCE)
			add_library( ${target} ${${target}_SOURCE})
		elseif( ${target_list}_SOURCE)
			add_library( ${target} ${${target_list}_SOURCE})
		endif()

	#Call add_executable while adding a EXECUTABLES target
	elseif( ${target_list} STREQUAL EXECUTABLES)

		if ( ${target}_SOURCE)
			add_executable( ${target} ${${target}_SOURCE})
		elseif( ${target_list}_SOURCE)
			add_executable( ${target} ${${target_list}_SOURCE})
		endif()

	endif()
	
endmacro()

#Set output directory of target, but we have to set different properties for static libraries and executables
macro( macro_set_output_directory target_list target)

	#Set ARCHIVE_OUTPUT_DIRECTORY while adding a STATIC_LIBRARIES target
	if ( ${target_list} STREQUAL STATIC_LIBRARIES)

		if ( ${target}_OUTPUT_DIRECTORY)
			set_target_properties( ${target} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${${target}_OUTPUT_DIRECTORY})
		elseif( ${target_list}_OUTPUT_DIRECTORY)
			set_target_properties( ${target} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${${target_list}_OUTPUT_DIRECTORY})
		endif()

	#Set RUNTIME_OUTPUT_DIRECTORY while adding a EXECUTABLES target
	elseif( ${target_list} STREQUAL EXECUTABLES)

		if ( ${target}_OUTPUT_DIRECTORY)
			set_target_properties( ${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${${target}_OUTPUT_DIRECTORY})
		elseif( ${target_list}_OUTPUT_DIRECTORY)
			set_target_properties( ${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${${target_list}_OUTPUT_DIRECTORY})
		endif()

	endif()

endmacro()

#Specify linked libraries
macro( macro_link_libraries target_list target)

	if ( ${target}_LINK_LIBRARIES)

		target_link_libraries( ${target} ${${target}_LINK_LIBRARIES})

	elseif( ${target_list}_LINK_LIBRARIES)

		target_link_libraries( ${target} ${${target_list}_LINK_LIBRARIES})

	endif()

endmacro()

#Set targets' compile definiitions
macro( macro_set_compile_definitions target_list target)

	if ( ${target}_COMPILE_DEFINITIONS)

		target_compile_definitions( ${target} PUBLIC ${${target}_COMPILE_DEFINITIONS})

	elseif( ${target_list}_COMPILE_DEFINITIONS)

		target_compile_definitions( ${target} PUBLIC ${${target_list}_COMPILE_DEFINITIONS})

	endif()

endmacro()

#Remove default static libraries' prefix in unix
#For some reasons we cannot assign sth as null with a defined null variable
#So we set the PREFIX property directly instread of setting the value of  XXX_build_PREFIX
macro( macro_remove_output_prefix target_list target)

	if ( ${target_list} STREQUAL STATIC_LIBRARIES)

		#By default, the prefix of static libraries in unix ls "lib"
		set_target_properties( ${target} PROPERTIES PREFIX "")

	endif()

endmacro()

macro( macro_create_all_build_target target_list)

	if ( ${target_list} STREQUAL STATIC_LIBRARIES)
		add_custom_target( all_lib_build)
	elseif( ${target_list} STREQUAL EXECUTABLES)
		add_custom_target( all_build)
	endif()

endmacro()

macro( macro_add_to_all target_list target)

	if ( ${target_list} STREQUAL STATIC_LIBRARIES)
		add_dependencies( all_lib_build ${target})
	elseif( ${target_list} STREQUAL EXECUTABLES)
		add_dependencies( all_build ${target})
	endif()

endmacro()
#properties supported in both STATIC_LIBRARIES and EXECUTABLES
set( SUPPORTED_PROPERTIES
	COMPILE_FLAGS
	OUTPUT_NAME
	LINK_FLAGS
	)

#Added all targets in [target] and deal with all members of all target
macro( macro_register_target_list target_list)

	#Get the source of the target_list
	macro_get_source( ${target_list})

	#Create a custom target depends on targets in target_list
	macro_create_all_build_target( ${target_list})

    #Access every item in the target_list
    foreach( iter ${${target_list}})
        
		#Get the source of the target
		macro_get_source( ${iter})
		
		#Added target
		macro_create_target( ${target_list} ${iter})

		#Set the the property of a target of inherit this property from target_list
		foreach ( property ${SUPPORTED_PROPERTIES})
			macro_set_or_inherit_property( ${target_list} ${iter} ${property})
		endforeach()

		#Set compiler definitions
		macro_set_compile_definitions( ${target_list} ${iter})

		#Set output directory of a target
        macro_set_output_directory( ${target_list} ${iter})

		#Link libraries of a target
		macro_link_libraries( ${target_list} ${iter})

		#Remove static libraries' default prefix
		macro_remove_output_prefix( ${target_list} ${iter})

		#Add all_build target's depency to target
		macro_add_to_all( ${target_list} ${iter})

    endforeach()

endmacro()
