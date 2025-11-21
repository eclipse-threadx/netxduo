if(NOT ALLOCATION_PARAMETER)
  execute_process(COMMAND bash "-c" "git rev-parse --verify HEAD|cut -c1-1"
                  OUTPUT_VARIABLE ALLOCATION_PARAMETER)
  math(EXPR ALLOCATION_PARAMETER "0x${ALLOCATION_PARAMETER}")
endif()

if(NOT TEST_SUBNET_SIZE)
  set(TEST_SUBNET_SIZE 4)
endif()

# NX_MAX_PORT is 0xffff.
math(EXPR PORT_NUMBER "65535 - (${ALLOCATION_PARAMETER} + 1) * 256")
set(INTERFACE_NUMBER ${PORT_NUMBER})
math(EXPR TMP "256 - ${TEST_SUBNET_SIZE}")
set(TEST_NETMASK 255.255.255.${TMP})

set(IP_BYTE_0 10)
set(IP_BYTE_1 10)
set(IP_BYTE_2 ${ALLOCATION_PARAMETER})
set(IP_BYTE_3 1)
set(IP_BYTE_4 2)

macro(network_config target)
  target_compile_definitions(
    ${target}
    PRIVATE
    -DINTEROPERABILITY_TEST_ENABLE_PARALLEL_PROCESSING
    -DTLS_TEST_IP_BYTE_0=${IP_BYTE_0}
    -DTLS_TEST_IP_BYTE_1=${IP_BYTE_1}
    -DTLS_TEST_IP_BYTE_2=${IP_BYTE_2}
    -DTLS_TEST_IP_BYTE_3=${IP_BYTE_3}
    -DREMOTE_IP_BYTE_0=${IP_BYTE_0}
    -DREMOTE_IP_BYTE_1=${IP_BYTE_1}
    -DREMOTE_IP_BYTE_2=${IP_BYTE_2}
    -DREMOTE_IP_BYTE_3=${IP_BYTE_4}
    -DDEVICE_SERVER_PORT=${PORT_NUMBER}
    -DNX_PCAP_SOURCE_NAME=\"veth${INTERFACE_NUMBER}\")
  set(${target}_interface veth${INTERFACE_NUMBER})
  set(${target}_ip ${IP_BYTE_0}.${IP_BYTE_1}.${IP_BYTE_2}.${IP_BYTE_3})
  math(EXPR INTERFACE_NUMBER "${INTERFACE_NUMBER} + 1")
  set(${target}_remote_interface veth${INTERFACE_NUMBER})
  set(${target}_remote_ip ${IP_BYTE_0}.${IP_BYTE_1}.${IP_BYTE_2}.${IP_BYTE_4})
  set(${target}_port ${PORT_NUMBER})

  # Increase numbers for next setup
  math(EXPR INTERFACE_NUMBER "${INTERFACE_NUMBER} + 1")
  math(EXPR IP_BYTE_3 "${IP_BYTE_3} + ${TEST_SUBNET_SIZE}")
  if(${IP_BYTE_3} GREATER 253)
    math(EXPR IP_BYTE_2 "${IP_BYTE_2} + 1")
    set(IP_BYTE_3 1)
  endif()
  math(EXPR IP_BYTE_4 "${IP_BYTE_3} + 1")
  math(EXPR PORT_NUMBER "${PORT_NUMBER} + 1")

endmacro()
