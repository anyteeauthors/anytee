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

#include <page_tables.h>

.section .page_tables, "aw"
.balign PAGE_SIZE

l2_enh_1WA:
    .set ADDR, 0x80000000
    .set COUNT, 1 /* N_ENH_DOMAINS */
    .rept   COUNT
    .8byte (PTE_SUPERPAGE | PTE_ENH_WA_FLAGS) + ADDR
    .set ADDR, ADDR + L2_BLOCK_SIZE
    .endr
    .balign PAGE_SIZE

l1_enh_domain_1WA:
    .8byte (PTE_SUPERPAGE | PTE_MEM_FLAGS) + 0x0        /* 1GB -> 0x00000000 - 0x3fffffff */
    .8byte (PTE_SUPERPAGE | PTE_MEM_FLAGS) + 0x40000000 /* 1GB -> 0x40000000 - 0x7fffffff */
    .8byte (PTE_TABLE) + l2_enh_1WA                     /* 2MB -> 0x80000000 - 0x80200000 */
    .set ADDR, 0xC0000000                               /* ... -> 0xC0000000 - 0x7F_FFFFFFFF */
    .rept   510
    .8byte (PTE_SUPERPAGE | PTE_MEM_FLAGS) + ADDR
    .set ADDR, ADDR + L1_BLOCK_SIZE
    .endr
    .balign PAGE_SIZE

.global root_page_table
root_page_table:
    .8byte (PTE_TABLE) + l1_enh_domain_1WA
    .balign PAGE_SIZE

l2_enh_1nWA:
    .set ADDR, 0x80000000
    .set COUNT, 1 /* N_ENH_DOMAINS */
    .rept   COUNT
    .8byte (PTE_SUPERPAGE | PTE_ENH_nWA_FLAGS) + ADDR
    .set ADDR, ADDR + L2_BLOCK_SIZE
    .endr
    .balign PAGE_SIZE

l1_enh_domain_1nWA:
    .8byte (PTE_SUPERPAGE | PTE_MEM_FLAGS) + 0x0        /* 1GB -> 0x00000000 - 0x3fffffff */
    .8byte (PTE_SUPERPAGE | PTE_MEM_FLAGS) + 0x40000000 /* 1GB -> 0x40000000 - 0x7fffffff */
    .8byte (PTE_TABLE) + l2_enh_1nWA                    /* 2MB -> 0x80000000 - 0x80200000 */
    .set ADDR, 0xC0000000                               /* ... -> 0xC0000000 - 0x7F_FFFFFFFF */
    .rept   510
    .8byte (PTE_SUPERPAGE | PTE_MEM_FLAGS) + ADDR
    .set ADDR, ADDR + L1_BLOCK_SIZE
    .endr
    .balign PAGE_SIZE

.global root_page_table_1nwA
root_page_table_1nwA:
    .8byte (PTE_TABLE) + l1_enh_domain_1nWA
    .balign PAGE_SIZE

l2_enh_1nA:
    .set ADDR, 0x80000000
    .set COUNT, 512 /* N_ENH_DOMAINS */
    .rept   COUNT
    .8byte (PTE_INVALID | PTE_ENH_nA_FLAGS) + ADDR
    .set ADDR, ADDR + L2_BLOCK_SIZE
    .endr
    .balign PAGE_SIZE

l1_enh_domain_1nA:
    .8byte (PTE_SUPERPAGE | PTE_MEM_FLAGS) + 0x0        /* 1GB -> 0x00000000 - 0x3fffffff */
    .8byte (PTE_SUPERPAGE | PTE_MEM_FLAGS) + 0x40000000 /* 1GB -> 0x40000000 - 0x7fffffff */
    .8byte (PTE_TABLE) + l2_enh_1nA                     /* 2MB -> 0x80000000 - 0x80200000 */
    .set ADDR, 0xC0000000                               /* ... -> 0xC0000000 - 0x7F_FFFFFFFF */
    .rept   510
    .8byte (PTE_SUPERPAGE | PTE_MEM_FLAGS) + ADDR
    .set ADDR, ADDR + L1_BLOCK_SIZE
    .endr
    .balign PAGE_SIZE

.global root_page_table_1nA
root_page_table_1nA:
    .8byte (PTE_TABLE) + l1_enh_domain_1nA
    .balign PAGE_SIZE

