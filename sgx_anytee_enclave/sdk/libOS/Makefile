# 
# Bao, a Lightweight Static Partitioning Hypervisor 
#
# Copyright (c) Bao Project (www.bao-project.org), 2019-
#
# Authors:
#      Jose Martins <jose.martins@bao-project.org>
#      Sandro Pinto <sandro.pinto@bao-project.org>
#
# Bao is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation, with a special exception exempting guest code from such
# license. See the COPYING file in the top-level directory for details. 
#
#


NAME := sgx_anytee_enclave
OPT_LEVEL = 2
DEBUG_LEVEL = 3

ifneq ($(MAKECMDGOALS), clean)
ifeq ($(PLATFORM),)
$(error Undefined platform)
endif
endif

SRC_DIR:=./src
BUILD_DIR:=build/$(PLATFORM)
TARGET:=$(BUILD_DIR)/$(NAME)
CORE_DIR:=$(SRC_DIR)/core
PLATFORM_DIR:=$(SRC_DIR)/platform/$(PLATFORM)
DRIVERS_DIR:=$(SRC_DIR)/drivers
SRC_DIRS:=$(SRC_DIR) $(CORE_DIR) $(PLATFORM_DIR)
INC_DIRS:=./inc

ifeq ($(wildcard $(PLATFORM_DIR)),)
$(error unsupported platform $(PLATFORM))
endif

-include $(SRC_DIR)/sources.mk
C_SRC+=$(addprefix $(SRC_DIR)/, $(src_c_srcs))

-include $(CORE_DIR)/sources.mk
C_SRC+=$(addprefix $(CORE_DIR)/, $(core_c_srcs))

-include $(PLATFORM_DIR)/plat.mk
-include $(PLATFORM_DIR)/sources.mk
C_SRC+=$(addprefix $(PLATFORM_DIR)/, $(plat_c_srcs))
ASM_SRC+=$(addprefix $(PLATFORM_DIR)/, $(plat_s_srcs))


SRC_DIRS+= $(foreach driver, $(drivers), $(DRIVERS_DIR)/$(driver))
INC_DIRS+= $(foreach driver, $(drivers), $(DRIVERS_DIR)/$(driver)/inc)
-include $(foreach driver, $(drivers), $(DRIVERS_DIR)/$(driver)/sources.mk)
C_SRC+=$(addprefix $(DRIVERS_DIR)/, $(driver_c_srcs))
ASM_SRC+=$(addprefix $(DRIVERS_DIR)/, $(driver_s_srcs))

ARCH_DIR:= $(SRC_DIR)/arch/$(ARCH)
SRC_DIRS+= $(ARCH_DIR)
INC_DIRS+= $(ARCH_DIR)/inc
-include $(ARCH_DIR)/arch.mk
-include $(ARCH_DIR)/sources.mk
C_SRC+=$(addprefix $(ARCH_DIR)/, $(arch_c_srcs))
ASM_SRC+=$(addprefix $(ARCH_DIR)/, $(arch_s_srcs))

LD_FILE:= $(SRC_DIR)/linker.ld
GEN_LD_FILE:= $(BUILD_DIR)/linker.ld
#C_SRC = $(foreach src_dir, $(SRC_DIRS), $(wildcard $(src_dir)/*.c))
#ASM_SRC = $(foreach src_dir, $(SRC_DIRS), $(wildcard $(src_dir)/*.S))
OBJS = $(C_SRC:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) \
	$(ASM_SRC:$(SRC_DIR)/%.S=$(BUILD_DIR)/%.o) \
	$(ENCLAVE_C_SRC:$(ENCLAVE_DIR)/%.c=$(BUILD_DIR)/%.o) \
	$(ENCLAVE_CPP_SRC:$(ENCLAVE_DIR)/%.cpp=$(BUILD_DIR)/%.o)

DEPS = $(OBJS:%=%.d) $(GEN_LD_FILE).d
DIRS:=$(sort $(dir $(OBJS) $(DEPS)))

CC=$(CROSS_COMPILE)gcc
CXX=$(CROSS_COMPILE)g++
AS=$(CROSS_COMPILE)as
LD=$(CROSS_COMPILE)ld
OBJCOPY=$(CROSS_COMPILE)objcopy
OBJDUMP=$(CROSS_COMPILE)objdump

GENERIC_FLAGS = $(ARCH_GENERIC_FLAGS) -O$(OPT_LEVEL) -g$(DEBUG_LEVEL) -gdwarf-3 -static
GENERIC_FLAGS += -I$(COMMON_DIR)/inc/ \
		 -I$(COMMON_DIR)/inc/tlibc \
		 -I$(COMMON_DIR)/inc/stdc++ \
		 -I$(SRC_DIR)/platform/$(PLATFORM)/inc \
		 -fdiagnostics-color=always -march=armv8.2-a

INC_DIRS += $(LINUX_SDK_DIR)/common/inc/tlibc
ASFLAGS = $(GENERIC_FLAGS) $(ARCH_ASFLAGS) 
CFLAGS = $(GENERIC_FLAGS) $(addprefix -I, $(INC_DIRS)) $(ARCH_CFLAGS) $(ENCLAVE_INC_DIR) $(ENCLAVE_C_FLAGS)
CPPFLAGS = $(GENERIC_FLAGS) $(ARCH_CPPFLAGS) $(addprefix -I, $(INC_DIRS)) $(ENCLAVE_INC_DIR) $(ENCLAVE_CPP_FLAGS)
ifneq ($(SINGLE_CORE),)
CPPFLAGS+=-DSINGLE_CORE=y
endif
LDFLAGS = $(GENERIC_FLAGS) $(ARCH_LDFLAGS) -nostartfiles -nostdlib



all: $(TARGET).bin

ifneq ($(MAKECMDGOALS), clean)
-include $(DEPS)
endif

.PHONY: $(TARGET).bin
$(TARGET).bin: $(TARGET).elf
	@$(OBJCOPY) -O binary $< $@
	cp $@ ../../

$(TARGET).elf: $(OBJS) $(GEN_LD_FILE)
	@ $(CC) $(LDFLAGS) $(ENCLAVE_INC_DIR) -T$(GEN_LD_FILE) -L$(LINUX_SDK_DIR)/../ $(ENCLAVE_OBJS) -o $@ $(OBJS) $(ENCLAVE_INC_DIR)  -lcpprt $(ENCLAVE_CPP_FLAGS) -lsgx_tsetjmp -lsgx_tsafecrt -ltlibc -lsgx_mm -lsgx_trts -lselib -ltlibc -ltlibthread -lsgx_tmm_rsrv -lcxx
	@$(OBJDUMP) -S $@ > $(TARGET).asm
	@$(OBJDUMP) -x -d --wide $@ > $(TARGET).lst

$(BUILD_DIR):
	@mkdir -p $@

$(OBJS): | $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(ENCLAVE_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(ENCLAVE_DIR)/%.cpp
	$(CXX) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@$(CXX) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.S
	@$(CC) $(ASFLAGS) $(CPPFLAGS) -c $< -o $@

$(GEN_LD_FILE): $(LD_FILE)
	@$(CXX) $(CPPFLAGS) -E -x assembler-with-cpp $< | grep "^[^#;]" > $@

.SECONDEXPANSION:

$(OBJS) $(DEPS): | $$(@D)/

$(DIRS):
	@mkdir -p $@


clean:
	@rm -rf build
	@rm -f *.elf
	@rm -f *.bin	
	@rm -f *.asm
	@rm -f *.lst

.PHONY: all clean
