# Azure RTOS NetX Duo

This advanced, industrial-grade TCP/IP network stack is designed specifically for deeply embedded real-time and IoT applications. Azure RTOS NetX Duo is a dual IPv4 and IPv6 network stack, while Azure RTOS NetX is the original IPv4 network stack, essentially a subset of Azure RTOS NetX Duo.

## Documentation

Documentation for this library can be found here: http://docs.microsoft.com/azure/rtos/netx-duo

## Repository Structure and Usage

### Branches & Releases

The master branch has the most recent code with all new features and bug fixes. It does not represent the latest General Availability (GA) release of the library.

### Releases

Each official release (preview or GA) will be tagged to mark the commit and push it into the Github releases tab, e.g. `v6.1-rel`.

### Directory layout

```
- addons
  - auto_ip, BSD, azure_iot, dhcp, cloud, dns, ftp, http, mdns, mqtt, nat, pop3, ppp, pppoe, smtp, sntp, telnet, tftp, web
- cmake
- common
  - inc
  - src
- crypto_libraries
  - inc
  - src
- nx_secure
  - inc
  - src
- ports
  - cortex_m0/gnu
    - inc
    - src
  - cortex_m3/gnu
    - inc
    - src
  - cortex_m4/gnu
    - inc
    - src
  - cortex_m7/gnu
    - inc
    - src
- samples
```

### Develop from the source code

NetX Duo has a couple of dependencies that are included as submodules. To clone the repo:

```bash
$ git clone https://github.com/azure-rtos/netxduo.git
$ git submodule update --init
```

## Azure IoT

NetX Duo includes [Azure IoT Middleware for Azure RTOS](https://github.com/azure-rtos/netxduo/tree/master/addons/azure_iot) (a.k.a IoT Middleware), a platform specific library that acts as a binding layer between the Azure RTOS and the [Azure SDK for Embedded C](https://github.com/Azure/azure-sdk-for-c/tree/master/sdk/docs/iot).

The IoT Middleware also includes Azure services integrations for:

### Device Update for IoT Hub

The [Device Update for IoT Hub](https://docs.microsoft.com/azure/iot-hub-device-update/understand-device-update) <sup>Public Preview</sup> is an Azure services for IoT solution to enable the over-the-air (OTA) easily. The IoT Middleware provides the module with simple APIs for device builder easily adding the OTA feature. Additional APIs, docs and sample projects can be found on the [feature/adu](https://aka.ms/azrtos-device-update-preview) branch.

### Azure Defender for IoT security

The Azure Defender for IoT security module provides a comprehensive security solution for Azure RTOS devices. Azure RTOS now ships with the Defender for IoT security module built-in and provides coverage for common threats and potential malicious activities.  The security module is part of the Azure IoT Middleware for Azure RTOS (addons/azure_iot/).  As the device connects to Azure IoT hub, Defender for IoT collectors gather network connectivity information and sends it to the Defender for IoT service for analysis. For details on how the security module works and the type of information it collects, refer to [Azure Defender for IoT security module](https://github.com/azure-rtos/netxduo/tree/v6.1_rel/addons/azure_iot/docs#azure-defender-for-iot-module) section in the Azure IoT document.

## Security

Azure RTOS provides OEMs with components to secure communication and to create code and data isolation using underlying 
MCU/MPU hardware protection mechanisms. It is ultimately the responsibility of the device builder to ensure the device 
fully meets the evolving security requirements associated with its specific use case.

## Licensing

License terms for using Azure RTOS are defined in the LICENSE.txt file of this repo. Please refer to this file for all 
definitive licensing information. No additional license fees are required for deploying Azure RTOS on hardware defined 
in the LICENSED-HARDWARE.txt file. If you are using hardware not defined in the LICENSED-HARDWARE.txt file or have 
licensing questions in general, please contact Microsoft directly at https://azure-rtos.ms-iot-contact.com/

## Contribution, feedback, issues, and professional support

If you encounter any bugs, have suggestions for new features, or if you would like to become an active contributor to 
this project, please follow the instructions provided in the contribution guideline for the corresponding repo.

For basic support, click Issues in the command bar or post a question to [Stack Overflow](http://stackoverflow.com/questions/tagged/azure-rtos+threadx) using the `threadx` and `azure-rtos` tags.

Professional support plans (https://azure.microsoft.com/en-us/support/options/) are available from Microsoft.

## Additional Resources

The following are references to additional Azure RTOS and Azure IoT in general:
|   |   |
|---|---|
| Azure RTOS Website: | https://azure.microsoft.com/en-us/services/rtos/ |
| Azure RTOS Sales Questions: | https://azure-rtos.ms-iot-contact.com/ |
| Microsoft Q/A for Azure IoT: | https://docs.microsoft.com/en-us/answers/products/azure?product=iot |
| Internet of Things Show: | https://aka.ms/iotshow |
| IoT Tech Community: | https://aka.ms/iottechcommunity |