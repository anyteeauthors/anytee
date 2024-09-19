# AnyTEE

Trusted Execution Environments (TEEs), e.g., Intel SGX and Arm TrustZone, are technologies widely available in Commercial Off-The-Shelf (COTS) devices to secure a broad spectrum of applications. Unfortunately, the vast design space of existing TEE mechanisms and protection models poses significant interoperability and compatibility challenges, which are even exacerbated by the new TEE extensions, e.g., Intel TDX and Arm CCA. In this paper, we propose AnyTEE. AnyTEE is an open-source framework that provides interoperability, extensibility, and portability across multiple Instruction Set Architectures (ISAs) by leveraging widely available hardware virtualization primitives. AnyTEE introduces the concept of hierarchical TEE execution modeling, enabling TEE composability, nesting, and/or customization, while facilitating the support of legacy, modern, and future TEE models. We have developed a reference implementation of AnyTEE for the SGX protection model (sdSGX) on an Arm and for the TrustZone protection model (sdTZ) on RISC-V. We extensively evaluated AnyTEE using microbenchmarks and real-world applications, and we concluded that our system achieves near-native performance (<3%).

# Folders
## anytee
- AnyTEE source code, based on the bao-hypervisor.

## linux
- sdSGX linux kernel driver

## sgx_anytee_enclave
- nbench: Linux native application
- sgx-nbench: SGX nbench port
- SGX-OpenSSL: Library and sample code (client and server) for SGX-OpenSSL
- SGX-openSSL-enh: enhancement using protected memory region
- sgxsdk: libOS based on the bao-baremetal guest, and other libraries for SGX enclaves

## optee_os
- optee os with support for RISC-V ISA running atop AnyTEE