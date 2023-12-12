# Set folder
set(TX_FOLDER "${PROJECT_SOURCE_DIR}/../threadx")
set(NXD_FOLDER "${PROJECT_SOURCE_DIR}/../../..")

# Add tx
add_subdirectory(${TX_FOLDER} threadx)

# Add nxd
set(NXD_ENABLE_FILE_SERVERS OFF CACHE BOOL "Disable fileX dependency by netxduo")
set(NXD_ENABLE_AZURE_IOT ON CACHE BOOL "Enable Azure IoT from netxduo")
add_subdirectory(${NXD_FOLDER} netxduo)

set_target_properties(threadx PROPERTIES FOLDER "azure_rtos")
set_target_properties(netxduo PROPERTIES FOLDER "azure_rtos")

set_target_properties(az_core PROPERTIES FOLDER "azure_iot_embedded_sdk")
set_target_properties(az_iot_common PROPERTIES FOLDER "azure_iot_embedded_sdk")
set_target_properties(az_iot_hub PROPERTIES FOLDER "azure_iot_embedded_sdk")
set_target_properties(az_iot_provisioning PROPERTIES FOLDER "azure_iot_embedded_sdk")
set_target_properties(az_nohttp PROPERTIES FOLDER "azure_iot_embedded_sdk")
set_target_properties(az_noplatform PROPERTIES FOLDER "azure_iot_embedded_sdk")

# Enable strict build flags for netxduo
if(THREADX_TOOLCHAIN STREQUAL "gnu")
  target_compile_options(
    netxduo
    PRIVATE -std=c99
            -Werror
            -Wall
            -Wextra
            -pedantic
            -fmessage-length=0
            -fsigned-char
            -ffunction-sections
            -fdata-sections
            -Wunused
            -Wuninitialized
            -Wmissing-declarations
            -Wconversion
            -Wpointer-arith
            -Wshadow
            -Wlogical-op
            -Wfloat-equal
            -fprofile-arcs
            -Wjump-misses-init
            -Wno-error=misleading-indentation)
endif()