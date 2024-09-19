######## SGX SDK Settings ########

SGX_SDK ?= ../../../sgx-samples/linux-sgx/sgxsdk
SGX_ARCH ?= aarch64
SGX_MODE ?= HW
SGX_DEBUG ?= 1
NBENCHDIR = $(PWD)/nbenchPortal/
ACC = $(APP_CROSS_COMPILE)gcc
ACXX = $(APP_CROSS_COMPILE)gcc
CC = $(ENCLAVE_CROSS_COMPILE)gcc
CXX = $(ENCLAVE_CROSS_COMPILE)gcc
PLATFORM ?= qemu-aarch64-virt


# SGX_COMMON_FLAGS :=
SGX_LIBRARY_PATH := $(SGX_SDK_ANYTEE)/lib
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

Urts_Library_Name := sgx_urts_anytee

App_Cpp_Files := App/App.cpp $(wildcard App/Edger8rSyntax/*.cpp) $(wildcard App/TrustedLibrary/*.cpp)
App_Include_Paths := -IInclude -IApp -I$(SGX_SDK)/include -InbenchPortal -I$(COMMON_DIR)/inc

App_C_Files := $(wildcard nbenchPortal/*.c)

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
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -L$(SGX_SDK_ANYTEE)/urts-anytee -l$(Urts_Library_Name) -lpthread -lm -static


App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_C_Objects := $(App_C_Files:.c=.o)
App_Name := app

######## Enclave Settings ########

Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice_sim
Crypto_Library_Name := sgx_tcrypto

ENCLAVE_DIR=$(PWD)/Enclave/
Enclave_Cpp_Files := $(PWD)/Enclave/Enclave.cpp $(wildcard Enclave/Edger8rSyntax/*.cpp) $(wildcard Enclave/TrustedLibrary/*.cpp)
Enclave_Include_Paths := -I$(PWD)/Include -I$(PWD)/Enclave  -I$(COMMON_DIR)/inc -I$(COMMON_DIR)/inc/tlibc -I$(COMMON_DIR)/inc/stlport -I$(NBENCHDIR)

Enclave_C_Flags := $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++
# Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
# 	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
# 	-Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
# 	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
# 	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
# 	-Wl,--defsym,__ImageBase=0 \
# 	-Wl,--version-script=Enclave/Enclave.lds
Enclave_Link_Flags :=  -L$(SGX_SDK_ANYTEE) \
 	-ltlibc  -l$(Trts_Library_Name) -lm


Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
# Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HYPER_DEBUG)
	@echo "The project has been built in debug hyper mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else ifeq ($(Build_Mode), HYPER_PRERELEASE)
	@echo "The project has been built in pre-release hyper mode."
else ifeq ($(Build_Mode), SIM_RELEASE)
	@echo "The project has been built in release simulation mode."
else
	@echo "The project has been built in release hyper mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(COMMON_DIR)/include
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	$(ACC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	$(ACXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects)
	$(MAKE) -C $(NBENCHDIR)
	$(ACXX) $(NBENCHDIR)emfloat.o $(NBENCHDIR)misc.o $(NBENCHDIR)nbench0.o\
		$(NBENCHDIR)nbench1.o $(NBENCHDIR)sysspec.o $(NBENCHDIR)hardware.o\
		 $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########
Enclave/Enclave_t.h: Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(COMMON_DIR)/inc
	@echo "GEN  =>  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h

$(Enclave_Name): Enclave/Enclave_t.c  $(Enclave_Cpp_Files)
	make -C $(SGX_SDK_ANYTEE)/libOS \
		ENCLAVE_DIR=$(PWD)/Enclave \
		ENCLAVE_C_SRC="$(ENCLAVE_DIR)/Enclave_t.c $(ENCLAVE_DIR)/encl_emfloat.c" \
		ENCLAVE_CPP_SRC="$(Enclave_Cpp_Files)" \
		PLATFORM=$(PLATFORM) \
		ENCLAVE_C_FLAGS="$(Enclave_C_Flags) $(Enclave_include_paths)" \
		ENCLAVE_CPP_FLAGS="$(Enclave_Cpp_Flags)" \
		CROSS_COMPILE=$(ENCLAVE_CROSS_COMPILE)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	$(MAKE) -C $(NBENCHDIR) clean
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* $(NBENCHDIR)*.o $(NBENCHDIR)*~ Enclave/*.o

