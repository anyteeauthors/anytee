/**
 * Bao, a Lightweight Static Partitioning Hypervisor
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      Jose Martins <jose.martins@bao-project.org>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details.
 *
 */

#ifndef __ARCH_TLB_H__
#define __ARCH_TLB_H__

#include <bao.h>
#include <arch/sysregs.h>
#include <arch/fences.h>

static inline void tlb_hyp_inv_va(vaddr_t va)
{
    asm volatile(
        "dsb  ish\n\t"
        "tlbi vae2is, %0\n\t"
        "dsb  ish\n\t"
        "isb\n\t" ::"r"(va >> 12));
}

static inline void tlb_hyp_inv_all()
{
    asm volatile(
        "dsb  ish\n\t"
        "tlbi alle2is\n\t"
        "dsb  ish\n\t"
        "isb\n\t");
}

static inline void tlb_vm_inv_va(asid_t vmid, vaddr_t va)
{
    uint64_t vttbr = 0;
    vttbr = MRS(VTTBR_EL2);
    bool switch_vmid =
        bit64_extract(vttbr, VTTBR_VMID_OFF, VTTBR_VMID_LEN) != vmid;

    if (switch_vmid) {
        MSR(VTTBR_EL2, ((vmid << VTTBR_VMID_OFF) & VTTBR_VMID_MSK));
        DSB(ish);
        ISB();
    }

    asm volatile("tlbi ipas2e1is, %0\n\t" ::"r"(va >> 12));

    if (switch_vmid) {
        DSB(ish);
        MSR(VTTBR_EL2, ((vmid << VTTBR_VMID_OFF) & VTTBR_VMID_MSK));
    }
}

static inline void tlb_vm_inv_all(asid_t vmid)
{
    uint64_t vttbr = 0;
    vttbr = MRS(VTTBR_EL2);
    bool switch_vmid =
        bit64_extract(vttbr, VTTBR_VMID_OFF, VTTBR_VMID_LEN) != vmid;

    if (switch_vmid) {
        MSR(VTTBR_EL2, ((vmid << VTTBR_VMID_OFF) & VTTBR_VMID_MSK));
        DSB(ish);
        ISB();
    }

    asm volatile("tlbi vmalls12e1is\n\t");

    if (switch_vmid) {
        DSB(ish);
        MSR(VTTBR_EL2, ((vmid << VTTBR_VMID_OFF) & VTTBR_VMID_MSK));
    }

    /* TODO */
    if (switch_vmid) {
        /* restore vttbr */
        MSR(VTTBR_EL2, vttbr);
        DSB(ish);
        ISB();
    }
}

#endif /* __ARCH_TLB_H__ */
