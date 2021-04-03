# Azure IoT Middleware for Azure RTOS

Azure IoT Middleware for Azure RTOS is a platform specific library that acts as a binding layer between the Azure RTOS and the [Azure SDK for Embedded C](https://github.com/Azure/azure-sdk-for-c/tree/master/sdk/docs/iot). Goals of this layer are following:

* Expose smart client interfaces (IoTHub_Client, DeviceProvisioning_Client) for the customers, to be consumed in their application.
* Orchestrate the interaction between Embedded C SDK and platform.
* Provide Azure RTOS platform initialization.
* IoT Plug and Play support.
* Security capabilities.
* Resource limitation aware.
* Protocol support.

## Getting Started

Azure IoT Middleware for Azure RTOS stays as an addon for the Azure RTOS NetXDuo. It facilitates the MQTT and TLS stacks that have been provided in the NetXDuo.

![diagram](./img/diagram.png)

### Build

The Azure IoT Middleware for Azure RTOS is built as part of the NetXDuo. Make sure you have defined the following *marcos* when building it:

Module | Marcos |
| --- | --- |
| Azure IoT Middleware for Azure RTOS | `NX_ENABLE_EXTENDED_NOTIFY_SUPPORT`<br> `NX_SECURE_ENABLE`<br> `NXD_MQTT_CLOUD_ENABLE`
| Azure Defender for IoT security module | `NX_ENABLE_IP_PACKET_FILTER`

**NOTE:** Azure Defender for IoT security module is enabled by default. You can define `NX_AZURE_DISABLE_IOT_SECURITY_MODULE` to disable it. [Learn more](#azure-defender-for-iot-security-module).

Follow [this example](/ports/cortex_m7/iar/inc/nx_port.h) to see how to define these *marcos* in the header file.

### Samples

For complete samples on how to get started on different devices with Azure IoT Middleware for Azure RTOS, see the following samples:

Manufacturer | Device | Samples |
| --- | --- | --- |
| Microchip | [ATSAME54-XPRO](https://www.microchip.com/developmenttools/productdetails/atsame54-xpro) | [GCC/CMake](https://github.com/azure-rtos/getting-started/tree/master/Microchip/ATSAME54-XPRO) • [IAR](https://aka.ms/azrtos-sample/e54-iar) • [MPLAB](https://aka.ms/azrtos-sample/e54-mplab)
| MXCHIP | [AZ3166](https://aka.ms/iot-devkit) | [GCC/CMake](https://github.com/azure-rtos/getting-started/tree/master/MXChip/AZ3166)
| NXP | [MIMXRT1060-EVK](https://www.nxp.com/design/development-boards/i-mx-evaluation-and-development-boards/mimxrt1060-evk-i-mx-rt1060-evaluation-kit:MIMXRT1060-EVK) | [GCC/CMake](https://github.com/azure-rtos/getting-started/tree/master/NXP/MIMXRT1060-EVK) • [IAR](https://aka.ms/azrtos-sample/rt1060-iar) • [MCUXpresso](https://aka.ms/azrtos-sample/rt1060-mcuxpresso)
| STMicroelectronics | [STM32F746GDISCOVERY](https://www.st.com/en/evaluation-tools/32f746gdiscovery.html) | [IAR](https://aka.ms/azrtos-sample/f746g-iar) • [STM32Cube](https://aka.ms/azrtos-sample/f746g-cubeide)
| STMicroelectronics | [B-L4S5I-IOT01](https://www.st.com/en/evaluation-tools/b-l4s5i-iot01a.html) / [B-L475E-IOT01](https://www.st.com/en/evaluation-tools/b-l475e-iot01a.html) | [GCC/CMake](https://github.com/azure-rtos/getting-started/tree/master/STMicroelectronics/STM32L4_L4%2B) • [IAR](https://aka.ms/azrtos-sample/l4s5-iar) • [STM32Cube](https://aka.ms/azrtos-sample/l4s5-cubeide)
| Renesas | [RX65N-RSK-2MB](https://www.renesas.com/us/en/products/microcontrollers-microprocessors/rx-32-bit-performance-efficiency-mcus/rx65n-2mb-starter-kit-plus-renesas-starter-kit-rx65n-2mb) | [GCC/CMake](https://github.com/azure-rtos/getting-started/tree/master/Renesas/RSK_RX65N_2MB) • [IAR](https://aka.ms/azrtos-samples/rx65n-rsk-2mb-iar) • [E2Studio CCRX](https://aka.ms/azrtos-samples/rx65n-rsk-2mb-ccrx) • [E2Studio GNURX](https://aka.ms/azrtos-samples/rx65n-rsk-2mb-gnurx)
| Renesas | [RX65N-Cloud-Kit](https://www.renesas.com/us/en/products/microcontrollers-microprocessors/rx-32-bit-performance-efficiency-mcus/rx65n-cloud-kit-renesas-rx65n-cloud-kit) | [E2Studio CCRX](https://aka.ms/azrtos-samples/rx65n-ck-ccrx) • [E2Studio GNURX](https://aka.ms/azrtos-samples/rx65n-ck-gnurx)

## Features

Basic features provided by [Azure SDK for Embedded C](https://github.com/Azure/azure-sdk-for-c/tree/master/sdk/docs/iot):
* Connect to IoTHub via MQTT.
* Send device to cloud (D2C) message.
* Receive cloud to device (C2D) message.
* Device Twins.
* Receive direct method.
* Authentication: SAS Token.

Enhanced features provided in middleware:
* Authentication: X.509 client certificate.
* Device Provisioning Service.
* JSON parser.

## Azure Defender for IoT security module

The [Azure Defender for IoT security module](https://docs.microsoft.com/azure/defender-for-iot/iot-security-azure-rtos) provides a comprehensive security solution for Azure RTOS devices. The middleware ships with the ASC for IoT Security Module built-in and enabled by default to detect common threats and potential malicious activities.

### Opt-out

To disable (opt-out) the module for your application, you can choose one of these two options:
* Define `NX_AZURE_DISABLE_IOT_SECURITY_MODULE` in NetXDuo header file such as [`nx_port.h`](/ports/cortex_m7/iar/inc/nx_port.h) when building the middleware.
* Call [`UINT nx_azure_iot_security_module_disable(NX_AZURE_IOT *nx_azure_iot_ptr)`](https://docs.microsoft.com/azure/defender-for-iot/azure-rtos-security-module-api#disable-azure-iot-security-module) in your application code.

### Data collection

By enabling the module, it analyzes inbound and outbound network activity on IPv4 and IPv6 supported protocols:  
* TCP 
* UDP
* ICMP

And with below data collected:  
* Local and remote address 
* Local and remote port 
* Bytes in 
* Bytes out 

### Resource requirements:

ASC for IoT module leverages existing Azure RTOS resources, and sends security messages in the background, without interfering with the user application, using the same connection to the IoT Hub.

The extra resource it will take on device and connection:

**Memory Footprint** (using default config - 4 unique monitored connection in IPv4 in an hour):
Toolchain | RAM | ROM |
| --- | --- | --- |
| IAR Embedded Workbench (iccarm) | 4Kb | 10Kb
| GUN ARM Embedded Toolchain (arm-gcc) | 4Kb | 13Kb

**Additional Connection**:
Connection Type | RAM | Network |
| --- | --- | --- |
| IPv4 | 52bytes | 36bytes
| IPv6 | 200bytes | 60bytes

So the total additional connection traffic will be:
*Total (in bytes) = Metadata (e.g. 300 bytes) + IPv4 Connections * 36 + IPv6 Connections * 60*

Learn [here](https://docs.microsoft.com/en-us/azure/defender-for-iot) for more information about Azure Defender for IoT.

## APIs

* [nx_azure_iot](./azure_rtos_iot.md)    
* [nx_azure_iot_hub_client](./azure_rtos_iot_hub_client.md)
* [nx_azure_iot_provisioning_client](./azure_rtos_iot_provisioning_client.md)
* [nx_azure_iot_json](./azure_rtos_iot_json.md)
* [nx_azure_iot_security_module](../azure_iot_security_module/docs/nx_azure_iot_security_module.md)

## Need Help?

* File an issue via [Github Issues](https://github.com/azure-rtos/netxduo/issues/new/choose).
* Check [previous questions](https://stackoverflow.com/questions/tagged/azure-rtos+netxduo) or ask new ones on StackOverflow using the [azure-rtos](https://stackoverflow.com/questions/tagged/azure-rtos) and [netxduo](https://stackoverflow.com/questions/tagged/netxduo) tags.

## Licensing

View [Licensing](https://github.com/azure-rtos/netxduo#licensing) of Azure RTOS NetXDuo.
