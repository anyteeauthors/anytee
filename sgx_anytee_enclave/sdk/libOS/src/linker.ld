/**
 * Bao, a Lightweight Static Partitioning Hypervisor
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      Jose Martins <jose.martins@bao-project.org>
 *      Sandro Pinto <sandro.pinto@bao-project.org>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details.
 *
 */

#include <plat.h>

MEMORY {
    RAM (rwx)    : ORIGIN = PLAT_MEM_BASE, LENGTH = PLAT_MEM_SIZE
}

ENTRY(_start)

SECTIONS {

    .start : {
        *(.start)
    }

    .text :  {
        *(.text*)
    }

    .rodata :  {
        *(.rodata*)
    }

    .data : {
        *(.data .data.*)
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.sdata .sdata.* .sdata2.*)
    }

    .bss (NOLOAD) :  {
        __bss_start = .;
        *(.bss* .sbss*)
        *(COMMON)
        __bss_end = .;
    }

    .stack : {
	. = ALIGN(4096);
	PROVIDE(_stack_base = .);
	. = _stack_base + 2*1024*1024; /* 2M of total stack size */
    }
    .heap : {
	. = ALIGN(4096);
	PROVIDE(_heap_base = .);
	. = . + 4*1024*1024; /* 4M of total heap size */
    }

    .page_tables : {
	. = ALIGN(0x00001000);
	*(.page_tables .page_tables.*)
    }

    /* give a few pages of shared memory */
    . = (PLAT_MEM_BASE + PLAT_MEM_SIZE - 0x10000);
    _sdsgx_shmem = .;

    . = 0x80000000;
    PROVIDE(_enh_domain1 = .);
    . = 0x80200000;
}
