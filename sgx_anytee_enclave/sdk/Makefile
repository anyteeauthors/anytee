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

SGX_SDK_ANYTEE ?= ../../../sgx_anytee_enclave/sdk
SGX_SDK ?= ../../../sgx_anytee_enclave/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= aarch64
SGX_DEBUG ?= 1
ACC = $(APP_CROSS_COMPILE)gcc
ACXX = $(APP_CROSS_COMPILE)gcc
CC = $(ENCLAVE_CROSS_COMPILE)gcc
CXX = $(ENCLAVE_CROSS_COMPILE)gcc


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
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## App Settings ########

Urts_Library_Name := sgx_urts_anytee

App_Cpp_Files := App/App.cpp $(wildcard App/Edger8rSyntax/*.cpp) $(wildcard App/TrustedLibrary/*.cpp)
App_Include_Paths := -IInclude -IApp -I$(COMMON_DIR)/inc


App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

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

App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags := -static -L$(SGX_SDK_ANYTEE) -l$(Urts_Library_Name)

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app

######## Enclave Settings ########

Trts_Library_Name := sgx_trts_sim
Service_Library_Name := sgx_tservice_sim
Crypto_Library_Name := sgx_tcrypto

ENCLAVE_DIR=$(PWD)/Enclave/
Enclave_Cpp_Files := Enclave/Enclave.cpp $(wildcard Enclave/Edger8rSyntax/*.cpp) $(wildcard Enclave/TrustedLibrary/*.cpp)

Enclave_Cpp_Files := $(subst Enclave/, $(ENCLAVE_DIR), $(Enclave_Cpp_Files))

Enclave_Include_Paths := -I$(PWD)/Include -I$(PWD)/Enclave -I$(SGX_SDK_ANYTEE)/include -I$(SGX_SDK_ANYTEE)/include/tlibc -I$(SGX_SDK_ANYTEE)/include/libcxx -I$(COMMON_DIR)/inc


# Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(MITIGATION_CFLAGS) -fno-builtin
Enclave_C_Flags := $(Enclave_Include_Paths)
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	# Enclave_C_Flags += -fstack-protector
else
	# Enclave_C_Flags += -fstack-protector-strong
endif

Enclave_Cpp_Flags := $(Enclave_C_Flags)
# Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
# Enclave_Link_Flags :=  -L$(SGX_TRUSTED_LIBRARY_PATH) \
# 	-l$(Trts_Library_Name) \
# 	-lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name)

Enclave_Link_Flags :=  -L$(SGX_TRUSTED_LIBRARY_PATH) \
 	-l$(Trts_Library_Name) \
# 	-lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name)\



Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
# Enclave_Config_File := Enclave/Enclave.config.xml
Enclave_Test_Key := Enclave/Enclave_private_test.pem

ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif

all: sdkurts sdktrts

libtrts.a:
	@make -C sdk/trts

libtlibc.a:
	@make -C sdk/tlibc

libtsafecrt.a:
	@make -C sdk/tsafecrt

libcxx.a:
	@make -C sdk/tlibcxx

libsgx_tmm_rsrv.a:
	@make -C sdk/tmm_rsrv

libtlibthread.a:
	@make -C sdk/tlibthread

libselib.a:
	@make -C sdk/selib/linux

libsgx_tsetjmp.a:
	@make -C sdk/tsetjmp

libsgx_mm.a:
	@make -C external/sgx-emm

libcpprt.a:
	@make -C sdk/cpprt all LIBUNWIND_DIR=linux/libunwind

libsgx_urts_anytee.a:
	@make -C urts-anytee all

libcpprt.a:
	@make -C sdk/cpprt/linux/libunwind clean
	@make -C sdk/cpprt/linux/libunwind
	@make -C sdk/cpprt all LIBUNWIND_DIR=linux/libunwind


sdktrts: libsgx_urts_anytee.a libtrts.a libtlibc.a libtsafecrt.a libcxx.a libsgx_tmm_rsrv.a libtlibthread.a libselib.a libsgx_tsetjmp.a libsgx_mm.a libcpprt.a
	find -name "*.a" | xargs -I {} cp {} ./  || true
	echo "Done"

libsgx_urts_anytee.a:
	@make -C urts-anytee

sdkurts: libsgx_urts_anytee.a
	echo "Done"

clean:
	find -name "*.a" -delete
	find -name "*.o" -delete
