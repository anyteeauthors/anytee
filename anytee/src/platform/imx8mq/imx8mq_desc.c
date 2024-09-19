#include <platform.h>

struct platform_desc platform = {
    .cpu_num = 1,
    .region_num = 1,
    .regions =  (struct mem_region[]) {
        {
            .base = 0x40000000,
            .size = 0xffffffff - 0x40000000, // 3 GiB
        },
        {
            .base = 0x100000000,
            .size = 0x13FFFFFFF-0x100000000, // 1 GiB
        }
    },

    .console = {
        .base = 0x30860000,
    },

    .arch = {

        .clusters =  {
            .num = 1,
            .core_num = (size_t[]) {4}
        },

        .gic = {
	    .gicd_addr = 0x38800000,
	    .gicr_addr = 0x38880000,
	    .gicc_addr = 0x31000000,
	    .gicv_addr = 0x31010000,
	    .gich_addr = 0x31020000,
            .maintenance_id = 25
        },
    }
};
