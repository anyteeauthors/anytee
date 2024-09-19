# Architecture definition
ARCH:=armv8
# CPU definition
CPU:=cortex-a53

GIC_VERSION:=GICV3

drivers = imx_uart

platform-cppflags =
platform-cflags = -mcpu=$(CPU)
platform-asflags =
platform-ldflags =
