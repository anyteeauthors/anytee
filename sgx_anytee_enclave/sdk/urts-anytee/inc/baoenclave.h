#ifndef __SDSGX_H__
#define __SDSGX_H__

#include <stdint.h>

#define SDSGX_DEVICE_IOCTL_BASE 'B'
#define SDSGX_DEVICE_IOC_CREATE_CMA        _IOW(SDSGX_DEVICE_IOCTL_BASE, 3, int)
#define SDSGX_DEVICE_IOC_RESUME_ENCLAVE	_IOW(SDSGX_DEVICE_IOCTL_BASE, 4, int)
#define SDSGX_DEVICE_IOC_CALL_ENCLAVE	_IOW(SDSGX_DEVICE_IOCTL_BASE, 5, int)
#define SDSGX_DEVICE_IOC_DESTROY_ENCLAVE	_IOW(SDSGX_DEVICE_IOCTL_BASE, 6, int)
#define SDSGX_DEVICE_IOC_PRINT_INFO	_IOW(SDSGX_DEVICE_IOCTL_BASE, 7, int)
#define SDSGX_DEVICE_IOC_ADD_RGN		_IOW(SDSGX_DEVICE_IOCTL_BASE, 8, int)
#define SDSGX_DEVICE_IOC_RING 		_IOW(SDSGX_DEVICE_IOCTL_BASE, 1, int)
#define SDSGX_DEVICE_IOC_READ 		_IOR(SDSGX_DEVICE_IOCTL_BASE, 0, int)

#define SDSGX_DEVICE_FILENAME "bao_enclave@0"
#define SDSGX_DEVICE "/dev/" SDSGX_DEVICE_FILENAME

#define SDSGX_CONFIG_FILENAME "enclave_config.bin"
#define SDSGX_CONFIG SDSGX_CONFIG_FILENAME

#define PAGE_SIZE 4096

typedef __UINTPTR_TYPE__ uintptr_t;


void sdsgx_place_config(char *, uintptr_t*, void**, size_t*, size_t*);
void sdsgx_free_space(size_t, uintptr_t, void*);

void sdsgx_exit();
void sdsgx_print_info();

#endif

