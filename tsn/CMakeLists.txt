# Each protocol handler is listed below. If you want
# to disable some / all of these, comment out the block(s) in question

set(SOURCES 
    # {{BEGIN_TARGET_SOURCES}}
    ${CMAKE_CURRENT_LIST_DIR}/src/nx_shaper.c
    ${CMAKE_CURRENT_LIST_DIR}/src/nx_mrp.c
    ${CMAKE_CURRENT_LIST_DIR}/src/nx_mvrp.c
    ${CMAKE_CURRENT_LIST_DIR}/src/nx_srp.c
    ${CMAKE_CURRENT_LIST_DIR}/src/nx_msrp.c
    # {{END_TARGET_SOURCES}}
)

target_sources(${PROJECT_NAME} PRIVATE ${SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/inc
)
