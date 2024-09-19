

CROSS_COMPILE = aarch64-none-linux-gnu-

SRC_DIR := src
OBJ_DIR := obj
INC_DIR := inc

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

TARGET := libsgx_urts_anytee.a

CFLAGS := -O2 -g -I$(INC_DIR) -I~/PhD/tools/arm-gnu-toolchain-11.3.rel1-x86_64-aarch64-none-elf/lib/gcc/aarch64-none-elf/11.3.1/include -I$(COMMON_DIR)/inc

$(info $(OBJS))

$(TARGET): $(OBJS)
	$(CROSS_COMPILE)ar rcs $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@$(CROSS_COMPILE)gcc $(CFLAGS) -c $<  -o $@


.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)
