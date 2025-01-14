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

#ifndef __VGIC_H__
#define __VGIC_H__

#include <bao.h>
#include <arch/gic.h>
#include <list.h>

struct vm;
struct vcpu;
struct gic_dscrp;

/**
 * TODO: optimize the vgic_int struct's size
 */
struct vgic_int {
    node_t node;
    struct vcpu *owner;
#if (GIC_VERSION != GICV2)
    unsigned long route;
    union {
        vcpuid_t redist;
        unsigned long route;
    } phys;
#endif
    spinlock_t lock;
    irqid_t id;
    uint8_t state;
    uint8_t prio;
    uint8_t cfg;
    uint8_t lr;
#if (GIC_VERSION == GICV2)
    union {
        uint8_t targets;
        struct {
            uint8_t act;
            uint8_t pend;
        } sgi;
    };
#endif
    bool hw;
    bool in_lr;
    bool enabled;
};

struct vgicd {
    struct vgic_int *interrupts;
    spinlock_t lock;
    size_t int_num;
    uint32_t CTLR;
    uint32_t TYPER;
    uint32_t IIDR;
};

struct vgicr {
    spinlock_t lock;
    uint64_t TYPER;
    uint32_t CTLR;
    uint32_t IIDR;
};

struct vgic_priv {
    struct {
        uint64_t ELSR;
        uint64_t LR[GICH_LR_MAX];
        uint32_t HCR;
        uint32_t VMCR;
        uint32_t APR[GIC_APR_MAX];
    } gich;
#if (GIC_VERSION != GICV2)
    struct vgicr vgicr;
#endif
    irqid_t curr_lrs[GIC_NUM_LIST_REGS];
    struct vgic_int interrupts[GIC_CPU_PRIV];
};

void vgic_init(struct vm *vm, const struct gic_dscrp *gic_dscrp);
void vgic_cpu_init(struct vcpu *vcpu);
void vgic_set_hw(struct vm *vm, irqid_t id);
void vgic_inject(struct vcpu *vcpu, irqid_t id, vcpuid_t source);
void vgic_inject_hw(struct vcpu *vcpu, irqid_t id);

/* VGIC INTERNALS */

enum vgic_reg_handler_info_id {
    VGIC_ISENABLER_ID,
    VGIC_ISPENDR_ID,
    VGIC_ISACTIVER_ID,
    VGIC_ICENABLER_ID,
    VGIC_ICPENDR_ID,
    VGIC_ICACTIVER_ID,
    VGIC_ICFGR_ID,
    VGIC_IROUTER_ID,
    VGIC_IPRIORITYR_ID,
    VGIC_ITARGETSR_ID,
    VGIC_REG_HANDLER_ID_NUM
};

struct vgic_reg_handler_info {
    void (*reg_access)(struct emul_access *, struct vgic_reg_handler_info *,
                       bool gicr_accces, cpuid_t vgicr_id);
    size_t alignment;
    size_t regid;
    vaddr_t regroup_base;
    size_t field_width;
    uint64_t (*read_field)(struct vcpu *, struct vgic_int *);
    bool (*update_field)(struct vcpu *, struct vgic_int *, uint64_t data);
    void (*update_hw)(struct vcpu *, struct vgic_int *);
};

/* interface for version agnostic vgic */
bool vgicd_emul_handler(struct emul_access *);
bool vgic_check_reg_alignment(struct emul_access *acc,
                              struct vgic_reg_handler_info *handlers);
bool vgic_add_lr(struct vcpu *vcpu, struct vgic_int *interrupt);
bool vgic_remove_lr(struct vcpu *vcpu, struct vgic_int *interrupt);
bool vgic_get_ownership(struct vcpu *vcpu, struct vgic_int *interrupt);
void vgic_yield_ownership(struct vcpu *vcpu, struct vgic_int *interrupt);
void vgic_emul_generic_access(struct emul_access *, struct vgic_reg_handler_info *,
                              bool, vcpuid_t);
void vgic_send_sgi_msg(struct vcpu *vcpu, cpumap_t pcpu_mask, irqid_t int_id);
size_t vgic_get_itln(const struct gic_dscrp *gic_dscrp);

/* interface for version specific vgic */
bool vgic_int_has_other_target(struct vcpu *vcpu, struct vgic_int *interrupt);
uint8_t vgic_int_ptarget_mask(struct vcpu *vcpu, struct vgic_int *interrupt);
void vgic_inject_sgi(struct vcpu *vcpu, struct vgic_int *interrupt, vcpuid_t source);

void vgic_save_state(struct vcpu *vcpu);
void vgic_restore_state(struct vcpu *vcpu);
bool vgic_int_get_enabled(struct vcpu *vcpu, uint64_t int_id);
void vgic_hw_commit(struct vcpu *vcpu, uint64_t int_id);

#endif /* __VGIC_H__ */
