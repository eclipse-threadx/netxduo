project( regression_test C)

#test prepare
execute_process( COMMAND "./test_prepare.sh" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target( test_prepare ALL COMMAND "./test_prepare.sh" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

#the directory for building test programs
set( BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})

#Basic compile flags and link flags.
set( COMPILE_FLAGS_LEVEL_0 "-m32 -ggdb -g3 -gdwarf-2")
set( GENERIC_LINK_FLAGS "-m32")

#The rules of properties' priority
set( STATIC_LIBRARIES_COMPILE_FLAGS ${COMPILE_FLAGS_LEVEL_0})
set( STATIC_LIBRARIES_LINK_FLAGS ${GENERIC_LINK_FLAGS})

#Set properties for all EXECUTABLES
set( EXECUTABLES_COMPILE_FLAGS ${COMPILE_FLAGS_LEVEL_0})
set( EXECUTABLES_LINK_FLAGS ${GENERIC_LINK_FLAGS})

#Generic compile definitions for frame test.
set( FRAME_TEST_GENERIC_COMPILE_DEFINITIONS TEST_FOR_FRAME)

#include config file of tls test frame
include( tls_test_frame_settings.cmake)

include( test_files.cmake)

set( tls_test_frame_LINK_LIBRARIES pthread)
list( APPEND tls_test_frame_COMPILE_DEFINITIONS ${FRAME_TEST_GENERIC_COMPILE_DEFINITIONS})
set( tls_test_frame_OUTPUT_DIRECTORY ${BUILD_DIR})

set( output_path ${CMAKE_CURRENT_BINARY_DIR})
set( file_test_list ${output_path}/TestList)
file( WRITE ${file_test_list} "")

foreach( test ${REGRESSION_TEST_LIST})
    set( exe ${test})
    list( APPEND EXECUTABLES ${exe})
    set( ${exe}_LINK_LIBRARIES pthread rt tls_test_frame)
    set( ${exe}_SOURCE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set( ${exe}_FILE_LIST ${${test}_FILE_LIST})
    set( ${exe}_OUTPUT_DIRECTORY ${BUILD_DIR})
    set( ${exe}_OUTPUT_NAME ${test})

    #Collect test names
    file( APPEND ${file_test_list} ${test}\n)
endforeach()
