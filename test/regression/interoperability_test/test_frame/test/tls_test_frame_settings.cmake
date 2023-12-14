#BRANCH_DIR and BUILD_DIR are needed.
#Describe tls_test_frame.a
list( APPEND STATIC_LIBRARIES tls_test_frame)
set( tls_test_frame_SOURCE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
include_directories( ${tls_test_frame_SOURCE_DIRECTORY})

#Include file list.
include( ${tls_test_frame_SOURCE_DIRECTORY}/tls_test_frame_FILE_LIST.cmake)
