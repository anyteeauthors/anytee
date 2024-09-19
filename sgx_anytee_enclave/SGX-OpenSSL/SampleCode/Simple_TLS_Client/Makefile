#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
ACC = $(APP_CROSS_COMPILE)gcc
ACXX = $(APP_CROSS_COMPILE)gcc
CC = $(ENCLAVE_CROSS_COMPILE)gcc
CXX = $(ENCLAVE_CROSS_COMPILE)gcc

OPENSSL_SGX_PATH = $(PWD)/../../OpenSSL_SGX
OPENSSL_SGX_INC = -I$(OPENSSL_SGX_PATH)/include
OPENSSL_LIBS = -lssl -lcrypto

SGX_LIBRARY_PATH := $(SGX_SDK_ANYTEE)/lib
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -gdwarf-3
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

# ifneq ($(SGX_MODE), HW)
# 	Urts_Library_Name := sgx_urts_sim
# else
# 	Urts_Library_Name := sgx_urts
# endif
Urts_Library_Name := sgx_urts_anytee

App_Cpp_Files := $(wildcard App/*.cpp)
App_Include_Paths := -IInclude -IApp -I$(SGX_SDK)/include -I$(COMMON_DIR)/inc


App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := -static -L$(SGX_SDK_ANYTEE)/urts-anytee -l$(Urts_Library_Name) 

# ifneq ($(SGX_MODE), HW)
# 	App_Link_Flags += -lsgx_uae_service_sim
# else
# 	App_Link_Flags += -lsgx_uae_service
# endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app

######## Enclave Settings ########

Trts_Library_Name := sgx_trts_sim
Service_Library_Name := sgx_tservice_sim
Crypto_Library_Name := sgx_tcrypto

ENCLAVE_DIR=$(PWD)/Enclave/

Enclave_Cpp_Files := $(wildcard Enclave/*.cpp)
Enclave_Cpp_Files := $(subst Enclave/, $(ENCLAVE_DIR), $(Enclave_Cpp_Files))

Enclave_Include_Paths := -I$(PWD)/Include -I$(PWD)/Enclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport $(OPENSSL_SGX_INC)

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
# Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
# 	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
# 	-L$(OPENSSL_SGX_PATH) $(OPENSSL_LIBS) \
# 	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
# 	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
# 	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
# 	-Wl,--defsym,__ImageBase=0 \
# 	-Wl,--version-script=Enclave/Enclave.lds

Enclave_Link_Flags := -L$(OPENSSL_SGX_PATH) $(OPENSSL_LIBS)

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(COMMON_DIR)/inc
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	$(ACC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp App/Enclave_u.c
	$(ACXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects)
	$(ACXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########

Enclave/Enclave_t.c: Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(COMMON_DIR)/inc
	@echo "GEN  =>  $@"

$(Enclave_Name): $(Enclave_Cpp_Files) Enclave/Enclave_t.c
	make -C ../../../sdk/libOS \
		ENCLAVE_DIR=$(PWD)/Enclave \
		ENCLAVE_C_SRC="$(ENCLAVE_DIR)/Enclave_t.c" \
		ENCLAVE_CPP_SRC="$(Enclave_Cpp_Files)" \
		ENCLAVE_INC_DIR="$(Enclave_Include_Paths)" \
		PLATFORM=$(PLATFORM) \
		ENCLAVE_C_FLAGS="$(Enclave_C_Flags) $(Enclave_Link_Flags)" \
		ENCLAVE_CPP_FLAGS="$(Enclave_Cpp_Flags) $(Enclave_Link_Flags)" \
		CROSS_COMPILE=aarch64-none-linux-gnu-
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	# @$(SGX_ENCLAVE_SIGNER) sign -ignore-init-sec-error -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@cp $(Enclave_Name) $@
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
