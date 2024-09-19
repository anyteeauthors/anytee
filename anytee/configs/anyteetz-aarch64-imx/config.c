#include <config.h>
// Linux Image
VM_IMAGE(linux_image, "../../../lloader/linux-aarch64-imx.bin");
// Linux VM configuration
struct vm_config linux = {
    .image = {
        .base_addr = 0x50200000,
        .load_addr = VM_IMAGE_OFFSET(linux_image),
        .size = VM_IMAGE_SIZE(linux_image),
    },
    .entry = 0x50200000,
    .cpu_affinity = 0x1,
    .platform = {
        .cpu_num = 1,
        .region_num = 1,
        .regions = (struct mem_region[]) {
            {
                .base = 0x50000000,
                .size = 0x30000000,
		.place_phys = 1,
		.phys = 0x50000000,
            }
        },
        .ipc_num = 1,
        .ipcs = (struct ipc[]) {
            {
                .base = 0x80000000,
                .size = 0x00200000,
                .shmem_id = 0,
            }
        },
        .dev_num = 4,
        .devs =  (struct dev_region[]) {
            {
                .pa = 0x00000000,
                .va = 0x00000000,
                .size = 0x38800000,
	    },
	    /* hole for gic */
	    {
                .pa = 0x38900000,
                .va = 0x38900000,
                .size = 0x40000000 - 0x38900000,
	    },
	    {
		.interrupt_num = 1,
		.interrupts = (irqid_t[]) { 27 }
	    },
	    {
		.interrupt_num = 128,
		.interrupts = (irqid_t[]) {
		    32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,
		    52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,
		    72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,
		    92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,
		    109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,
		    124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,
		    139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,
		    154,155,156,157,158,159,
		},
	    }
        },
        .arch = {
            .gic = {
		.gicd_addr = 0x38800000,
		.gicr_addr = 0x38880000,
            }
        }
    }
};

VM_IMAGE(optee_os_image, "../../../optee_os/out/arm-plat-imx/core/tee-pager_v2.bin");
struct vm_config optee_os = {
    .image = {
        .base_addr = 0xfe000000,
        .load_addr = VM_IMAGE_OFFSET(optee_os_image),
        .size = VM_IMAGE_SIZE(optee_os_image),
    },
    .entry = 0xfe000000,
    .cpu_affinity = 0x1,
    .children_num = 1,
    .children = (struct vm_config*[]) { &linux },
    .platform = {
        .cpu_num = 1,
        .region_num = 1,
        .regions = (struct mem_region[]) {
            {
                .base = 0xfe000000,
                .size = 0x00F00000, // 15 MB
            }
        },
        .ipc_num = 1,
        .ipcs = (struct ipc[]) {
            {
                .base = 0x80000000,
                .size = 0x00200000,
                .shmem_id = 0,
            }
        },
        .dev_num = 2,
        .devs = (struct dev_region[]) {
            {
                .pa = 0x00000000,
                .va = 0x00000000,
                .size = 0x38800000,
	    },
	    /* hole for gic */
	    {
                .pa = 0x38900000,
                .va = 0x38900000,
                .size = 0x40000000 - 0x38900000,
	    },
        },
    },
};

struct config config = {

    CONFIG_HEADER
    .shmemlist_size = 1,
    .shmemlist = (struct shmem[]) {
        {
            .size = 0x00200000, // 2 MB
        }
    },
    .vmlist_size = 1,
    .vmlist = {
        &optee_os
    }
};
