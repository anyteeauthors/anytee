/**
 * Bao, a Lightweight Static Partitioning Hypervisor
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      Jose Martins <jose.martins@bao-project.org>
 *      Angelo Ruocco <angeloruocco90@gmail.com>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details.
 *
 */

#include <arch/gic.h>
#include <arch/gicv2.h>

#include <bit.h>
#include <spinlock.h>
#include <cpu.h>
#include <interrupts.h>
#include <vm.h>

extern volatile struct gicd_hw gicd;
extern spinlock_t gicd_lock;

volatile struct gicc_hw gicc __attribute__((section(".devices"), aligned(PAGE_SIZE)));
volatile struct gich_hw gich __attribute__((section(".devices"), aligned(PAGE_SIZE)));

static cpuid_t gic_cpu_map[GIC_MAX_TARGETS];

size_t NUM_LRS;

size_t gich_num_lrs()
{
    return ((gich.VTR & GICH_VTR_MSK) >> GICH_VTR_OFF) + 1;
}

uint32_t gich_get_apr(size_t i) 
{
     if(i == 0) {
        return gich.APR;
    } else {
        return 0;
    }   
}

void gich_set_apr(size_t i, uint32_t val) 
{
    if(i == 0) {
        gich.APR = val;
    }
}
/* TODO End */

static inline void gicc_init()
{
    for (size_t i = 0; i < gich_num_lrs(); i++) {
        gich.LR[i] = 0;
    }

    gicc.PMR = GIC_LOWEST_PRIO;
    gicc.CTLR |= GICC_CTLR_EN_BIT | GICC_CTLR_EOImodeNS_BIT;

    gich.HCR |= GICH_HCR_LRENPIE_BIT;
    
    uint32_t sgi_targets = gicd.ITARGETSR[0] & BIT32_MASK(0, GIC_TARGET_BITS);
    ssize_t gic_cpu_id = 
        bitmap_find_nth((bitmap_t*)&sgi_targets, GIC_TARGET_BITS, 1, 0, true);
    if(gic_cpu_id < 0) {
        ERROR("cant find gic cpu id");
    }

    gic_cpu_map[cpu.id] = (cpuid_t)gic_cpu_id;
}

void gicc_save_state(struct gicc_state *state)
{
    state->CTLR = gicc.CTLR;
    state->PMR = gicc.PMR;
    state->BPR = gicc.BPR;
    state->IAR = gicc.IAR;
    state->EOIR = gicc.EOIR;
    state->RPR = gicc.RPR;
    state->HPPIR = gicc.HPPIR;
    state->priv_ISENABLER = gicd.ISENABLER[0];

    for (size_t i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
        state->priv_IPRIORITYR[i] = gicd.IPRIORITYR[i];
    }

    state->HCR = gich.HCR;
    for (size_t i = 0; i < gich_num_lrs(); i++) {
        state->LR[i] = gich.LR[i];
    }
}

void gicc_restore_state(struct gicc_state *state)
{
    gicc.CTLR = state->CTLR;
    gicc.PMR = state->PMR;
    gicc.BPR = state->BPR;
    gicc.IAR = state->IAR;
    gicc.EOIR = state->EOIR;
    gicc.RPR = state->RPR;
    gicc.HPPIR = state->HPPIR;
    gicd.ISENABLER[0] = state->priv_ISENABLER;

    for (size_t i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
        gicd.IPRIORITYR[i] = state->priv_IPRIORITYR[i];
    }

    gich.HCR = state->HCR;
    for (size_t i = 0; i < gich_num_lrs(); i++) {
        gich.LR[i] = state->LR[i];
    }
}

void gic_cpu_init()
{
    for (size_t i = 0; i < GIC_NUM_INT_REGS(GIC_CPU_PRIV); i++) {
        /**
         * Make sure all private interrupts are not enabled, non pending,
         * non active.
         */
        gicd.ICENABLER[i] = -1;
        gicd.ICPENDR[i] = -1;
        gicd.ICACTIVER[i] = -1;
    }

    /* Clear any pending SGIs. */
    for (size_t i = 0; i < GIC_NUM_SGI_REGS; i++) {
        gicd.CPENDSGIR[i] = -1;
    }

    for (size_t i = 0; i < GIC_NUM_PRIO_REGS(GIC_CPU_PRIV); i++) {
        gicd.IPRIORITYR[i] = -1;
    }

    gicc_init();
}

void gic_map_mmio()
{
    mem_map_dev(&cpu.as, (vaddr_t)&gicc, platform.arch.gic.gicc_addr,
                NUM_PAGES(sizeof(gicc)));
    mem_map_dev(&cpu.as, (vaddr_t)&gich, platform.arch.gic.gich_addr,
                NUM_PAGES(sizeof(gich)));
    mem_map_dev(&cpu.as, (vaddr_t)&gicd, platform.arch.gic.gicd_addr,
                NUM_PAGES(sizeof(gicd)));
}

void gic_send_sgi(cpuid_t cpu_target, irqid_t sgi_num)
{
    if (sgi_num < GIC_MAX_SGIS && cpu_target < GIC_MAX_TARGETS) {
        gicd.SGIR = 
            (1UL << (GICD_SGIR_CPUTRGLST_OFF + gic_cpu_map[cpu_target])) |
            (sgi_num & GICD_SGIR_SGIINTID_MSK);
    }
}

static inline uint8_t gic_translate_cpu_to_trgt(uint8_t cpu_targets) {
    uint8_t gic_targets = 0;
    for(size_t i = 0; i < GIC_MAX_TARGETS; i++) {
        if((1 << i) & cpu_targets) {
            gic_targets |= (1 << gic_cpu_map[i]);
        }
    }
    return gic_targets;
}

void gicd_set_trgt(irqid_t int_id, uint8_t cpu_targets)
{
    size_t reg_ind = GIC_TARGET_REG(int_id);
    size_t off = GIC_TARGET_OFF(int_id);
    uint32_t mask = BIT32_MASK(off, GIC_TARGET_BITS);

    spin_lock(&gicd_lock);

    gicd.ITARGETSR[reg_ind] = (gicd.ITARGETSR[reg_ind] & ~mask) | 
        ((gic_translate_cpu_to_trgt(cpu_targets) << off) & mask);

    spin_unlock(&gicd_lock);
}

void gic_set_prio(irqid_t int_id, uint8_t prio)
{
    gicd_set_prio(int_id, prio);
}

uint8_t gic_get_prio(irqid_t int_id)
{
    return gicd_get_prio(int_id);
}

void gic_set_icfgr(irqid_t int_id, uint8_t cfg)
{
    gicd_set_icfgr(int_id, cfg);
}

bool gic_get_pend(irqid_t int_id)
{
    return gicd_get_pend(int_id);
}

void gic_set_act(irqid_t int_id, bool act)
{
    gicd_set_act(int_id, act);
}

bool gic_get_act(irqid_t int_id)
{
    return gicd_get_act(int_id);
}

void gic_set_enable(irqid_t int_id, bool en)
{
    gicd_set_enable(int_id, en);
}

void gic_set_pend(irqid_t int_id, bool pend)
{
    if (gic_is_sgi(int_id)) {
        size_t reg_ind = GICD_SGI_REG(int_id);
        size_t off = GICD_SGI_OFF(int_id);

        if (pend) {
            gicd.SPENDSGIR[reg_ind] = (1U) << (off + cpu.id);
        } else {
            gicd.CPENDSGIR[reg_ind] = BIT32_MASK(off, 8);
        }
    } else {
        gicd_set_pend(int_id, pend);
    }
}
