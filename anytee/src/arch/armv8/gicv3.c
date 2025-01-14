/**
 * Bao, a Lightweight Static Partitioning Hypervisor
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      Jose Martins <jose.martins@bao-project.org>
 *      David Cerdeira <davidmcerdeira@gmail.com>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details.
 *
 */

#include <arch/gic.h>
#include <arch/gicv3.h>

#include <cpu.h>
#include <mem.h>
#include <platform.h>
#include <interrupts.h>
#include <fences.h>

extern volatile struct gicd_hw gicd;
volatile struct gicr_hw *gicr;

static spinlock_t gicd_lock;
static spinlock_t gicr_lock;

size_t NUM_LRS;

size_t gich_num_lrs()
{
    return ((MRS(ICH_VTR_EL2) & ICH_VTR_MSK) >> ICH_VTR_OFF) + 1;
}

static inline void gicc_init()
{
    /* Enable system register interface i*/
    MSR(ICC_SRE_EL2, ICC_SRE_SRE_BIT);
    ISB();

    for (size_t i = 0; i < gich_num_lrs(); i++) {
        gich_write_lr(i, 0);
    }

    MSR(ICC_PMR_EL1, GIC_LOWEST_PRIO);
    MSR(ICC_BPR1_EL1, 0x0);
    MSR(ICC_CTLR_EL1, ICC_CTLR_EOIMode_BIT);
    MSR(ICH_HCR_EL2, MRS(ICH_HCR_EL2) | ICH_HCR_LRENPIE_BIT);
    MSR(ICC_IGRPEN1_EL1, ICC_IGRPEN_EL1_ENB_BIT);
}

static inline void gicr_init()
{
    gicr[cpu.id].ICENABLER0 = -1;
    gicr[cpu.id].ICPENDR0 = -1;
    gicr[cpu.id].ICACTIVER0 = -1;

    for (size_t i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
        gicr[cpu.id].IPRIORITYR[i] = -1;
    }
}

void gicc_save_state(struct gicc_state *state)
{
    state->PMR = MRS(ICC_PMR_EL1);
    state->BPR = MRS(ICC_BPR1_EL1);
    state->priv_ISENABLER = gicr[cpu.id].ISENABLER0;

    for (size_t i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
        state->priv_IPRIORITYR[i] = gicr[cpu.id].IPRIORITYR[i];
    }

    state->HCR = MRS(ICH_HCR_EL2);
    for (size_t i = 0; i < gich_num_lrs(); i++) {
        state->LR[i] = gich_read_lr(i);
    }
}

void gicc_restore_state(struct gicc_state *state)
{
    MSR(ICC_SRE_EL2, ICC_SRE_SRE_BIT);
    MSR(ICC_CTLR_EL1, ICC_CTLR_EOIMode_BIT);
    MSR(ICC_IGRPEN1_EL1, ICC_IGRPEN_EL1_ENB_BIT);
    MSR(ICC_PMR_EL1, state->PMR);
    MSR(ICC_BPR1_EL1, state->BPR);
    gicr[cpu.id].ISENABLER0 = state->priv_ISENABLER;

    for (size_t i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
        gicr[cpu.id].IPRIORITYR[i] = state->priv_IPRIORITYR[i];
    }

    MSR(ICH_HCR_EL2, state->HCR);
    for (size_t i = 0; i < gich_num_lrs(); i++) {
        gich_write_lr(i, state->LR[i]);
    }
}

void gic_cpu_init()
{
    gicr_init();
    gicc_init();
}

void gic_map_mmio()
{
    mem_map_dev(&cpu.as, (vaddr_t)&gicd, platform.arch.gic.gicd_addr,
                NUM_PAGES(sizeof(gicd)));
    size_t gicr_size = NUM_PAGES(sizeof(struct gicr_hw)) * platform.cpu_num;
    gicr = (struct gicr_hw *)mem_alloc_vpage(&cpu.as, SEC_HYP_GLOBAL, NULL_VA, gicr_size);
    mem_map_dev(&cpu.as, (vaddr_t)gicr, platform.arch.gic.gicr_addr, gicr_size);
}


void gicr_set_prio(irqid_t int_id, uint8_t prio, cpuid_t gicr_id)
{
    size_t reg_ind = GIC_PRIO_REG(int_id);
    size_t off = GIC_PRIO_OFF(int_id);
    uint32_t mask = BIT32_MASK(off, GIC_PRIO_BITS);

    spin_lock(&gicr_lock);

    gicr[gicr_id].IPRIORITYR[reg_ind] =
        (gicr[gicr_id].IPRIORITYR[reg_ind] & ~mask) | ((prio << off) & mask);

    spin_unlock(&gicr_lock);
}

uint8_t gicr_get_prio(irqid_t int_id, cpuid_t gicr_id)
{
    size_t reg_ind = GIC_PRIO_REG(int_id);
    size_t off = GIC_PRIO_OFF(int_id);

    spin_lock(&gicr_lock);

    uint8_t prio =
        gicr[gicr_id].IPRIORITYR[reg_ind] >> off & BIT32_MASK(off, GIC_PRIO_BITS);

    spin_unlock(&gicr_lock);

    return prio;
}

void gicr_set_icfgr(irqid_t int_id, uint8_t cfg, cpuid_t gicr_id)
{
    size_t reg_ind = (int_id * GIC_CONFIG_BITS) / (sizeof(uint32_t) * 8);
    size_t off = (int_id * GIC_CONFIG_BITS) % (sizeof(uint32_t) * 8);
    uint32_t mask = ((1U << GIC_CONFIG_BITS) - 1) << off;

    spin_lock(&gicr_lock);

    if (reg_ind == 0) {
        gicr[gicr_id].ICFGR0 =
            (gicr[gicr_id].ICFGR0 & ~mask) | ((cfg << off) & mask);
    } else {
        gicr[gicr_id].ICFGR1 =
            (gicr[gicr_id].ICFGR1 & ~mask) | ((cfg << off) & mask);
    }

    spin_unlock(&gicr_lock);
}

void gicr_set_pend(irqid_t int_id, bool pend, cpuid_t gicr_id)
{
    spin_lock(&gicr_lock);
    if (pend) {
        gicr[gicr_id].ISPENDR0 = (1U) << (int_id);
    } else {
        gicr[gicr_id].ICPENDR0 = (1U) << (int_id);
    }
    spin_unlock(&gicr_lock);
}

bool gicr_get_pend(irqid_t int_id, cpuid_t gicr_id)
{
    if (gic_is_priv(int_id)) {
        return !!(gicr[gicr_id].ISPENDR0 & GIC_INT_MASK(int_id));
    } else {
        return false;
    }
}

void gicr_set_act(irqid_t int_id, bool act, cpuid_t gicr_id)
{
    spin_lock(&gicr_lock);

    if (act) {
        gicr[gicr_id].ISACTIVER0 = GIC_INT_MASK(int_id);
    } else {
        gicr[gicr_id].ICACTIVER0 = GIC_INT_MASK(int_id);
    }

    spin_unlock(&gicr_lock);
}

bool gicr_get_act(irqid_t int_id, cpuid_t gicr_id)
{
    if (gic_is_priv(int_id)) {
        return !!(gicr[gicr_id].ISACTIVER0 & GIC_INT_MASK(int_id));
    } else {
        return false;
    }
}

void gicr_set_enable(irqid_t int_id, bool en, cpuid_t gicr_id)
{
    uint32_t bit = GIC_INT_MASK(int_id);

    spin_lock(&gicr_lock);
    if (en)
        gicr[gicr_id].ISENABLER0 = bit;
    else
        gicr[gicr_id].ICENABLER0 = bit;
    spin_unlock(&gicr_lock);
}

void gicd_set_route(irqid_t int_id, unsigned long route)
{
    if (gic_is_priv(int_id)) return;

    spin_lock(&gicd_lock);

    gicd.IROUTER[int_id] = route & GICD_IROUTER_AFF_MSK;

    spin_unlock(&gicd_lock);
}

void gic_send_sgi(cpuid_t cpu_target, irqid_t sgi_num)
{
    if (sgi_num < GIC_MAX_SGIS) {
        unsigned long mpidr = cpu_id_to_mpidr(cpu_target) & MPIDR_AFF_MSK;
        /* We only support two affinity levels */
        uint64_t sgi = (MPIDR_AFF_LVL(mpidr, 1) << ICC_SGIR_AFF1_OFFSET) |
                       (1UL << MPIDR_AFF_LVL(mpidr, 0)) |
                       (sgi_num << ICC_SGIR_SGIINTID_OFF);             
        MSR(ICC_SGI1R_EL1, sgi);
    }
}

void gic_set_prio(irqid_t int_id, uint8_t prio)
{
    if (!gic_is_priv(int_id)) {
        gicd_set_prio(int_id, prio);
    } else {
        gicr_set_prio(int_id, prio, cpu.id);
    }
}

uint8_t gic_get_prio(irqid_t int_id)
{
    if (!gic_is_priv(int_id)) {
        return gicd_get_prio(int_id);
    } else {
        return gicr_get_prio(int_id, cpu.id);
    }
}

void gic_set_icfgr(irqid_t int_id, uint8_t cfg)
{
    if (!gic_is_priv(int_id)) {
        gicd_set_icfgr(int_id, cfg);
    } else {
        gicr_set_icfgr(int_id, cfg, cpu.id);
    }
}

void gic_set_pend(irqid_t int_id, bool pend)
{
    if (!gic_is_priv(int_id)) {
        gicd_set_pend(int_id, pend);
    } else {
        gicr_set_pend(int_id, pend, cpu.id);
    }
}

bool gic_get_pend(irqid_t int_id)
{
    if (!gic_is_priv(int_id)) {
        return gicd_get_pend(int_id);
    } else {
        return gicr_get_pend(int_id, cpu.id);
    }
}

void gic_set_act(irqid_t int_id, bool act)
{
    if (!gic_is_priv(int_id)) {
        gicd_set_act(int_id, act);
    } else {
        gicr_set_act(int_id, act, cpu.id);
    }
}

bool gic_get_act(irqid_t int_id)
{
    if (!gic_is_priv(int_id)) {
        return gicd_get_act(int_id);
    } else {
        return gicr_get_act(int_id, cpu.id);
    }
}

void gic_set_enable(irqid_t int_id, bool en)
{
    if (!gic_is_priv(int_id)) {
        gicd_set_enable(int_id, en);
    } else {
        gicr_set_enable(int_id, en, cpu.id);
    }
}

