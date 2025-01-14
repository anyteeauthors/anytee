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

#include <arch/vgic.h>
#include <arch/vgicv3.h>

#include <bit.h>
#include <spinlock.h>
#include <cpu.h>
#include <interrupts.h>
#include <vm.h>

#define GICR_IS_REG(REG, offset)            \
    (((offset) >= offsetof(struct gicr_hw, REG)) && \
     (offset) < (offsetof(struct gicr_hw, REG) + sizeof(gicr[0].REG)))
#define GICR_REG_OFF(REG) (offsetof(struct gicr_hw, REG) & 0x1ffff)
#define GICR_REG_MASK(ADDR) ((ADDR)&0x1ffff)


bool vgic_int_has_other_target(struct vcpu *vcpu, struct vgic_int *interrupt)
{
    bool priv = gic_is_priv(interrupt->id);
    bool routed_here =
        !priv && !(interrupt->phys.route ^ (MRS(MPIDR_EL1) & MPIDR_AFF_MSK));
    bool route_valid = interrupt->phys.route != GICD_IROUTER_INV;
    bool any = !priv && vgic_broadcast(vcpu, interrupt);
    return any || (!routed_here && route_valid);
}

uint8_t vgic_int_ptarget_mask(struct vcpu *vcpu, struct vgic_int *interrupt)
{
    if (vgic_broadcast(vcpu, interrupt)) {
        return vcpu->vm->cpus & ~(1U << vcpu->phys_id);
    } else {
        return (1 << interrupt->phys.route);
    }
}

bool vgic_int_set_route(struct vcpu *vcpu, struct vgic_int *interrupt, 
                        unsigned long route)
{
    unsigned long phys_route;
    unsigned long prev_route = interrupt->route;

    if (gic_is_priv(interrupt->id)) return false;

    if (route & GICD_IROUTER_IRM_BIT) {
        phys_route = cpu_id_to_mpidr(vcpu->phys_id);
    } else {
        struct vcpu *tvcpu =
            vm_get_vcpu_by_mpidr(vcpu->vm, route & MPIDR_AFF_MSK);
        if (tvcpu != NULL) {
            phys_route = cpu_id_to_mpidr(tvcpu->phys_id) & MPIDR_AFF_MSK;
        } else {
            phys_route = GICD_IROUTER_INV;
        }
    }
    interrupt->phys.route = phys_route;

    interrupt->route = route & GICD_IROUTER_RES0_MSK;
    return prev_route != interrupt->route;
}

unsigned long vgic_int_get_route(struct vcpu *vcpu, struct vgic_int *interrupt)
{
    if (gic_is_priv(interrupt->id)) return 0;
    return interrupt->route;
}

void vgic_int_set_route_hw(struct vcpu *vcpu, struct vgic_int *interrupt)
{
    gicd_set_route(interrupt->id, interrupt->phys.route);
}

void vgicr_emul_ctrl_access(struct emul_access *acc,
                            struct vgic_reg_handler_info *handlers,
                            bool gicr_access, vcpuid_t vgicr_id)
{
    if (!acc->write) {
        vcpu_writereg(cpu.vcpu, acc->reg, 0);
    }
}

void vgicr_emul_typer_access(struct emul_access *acc,
                             struct vgic_reg_handler_info *handlers,
                             bool gicr_access, vcpuid_t vgicr_id)
{
    if (!acc->write) {
        struct vcpu *vcpu = vm_get_vcpu(cpu.vcpu->vm, vgicr_id);
        vcpu_writereg(cpu.vcpu, acc->reg, vcpu->arch.vgic_priv.vgicr.TYPER);
    }
}

void vgicr_emul_pidr_access(struct emul_access *acc,
                            struct vgic_reg_handler_info *handlers,
                            bool gicr_access, vcpuid_t vgicr_id)
{
    if (!acc->write) {
        unsigned long val = 0;
        cpuid_t pgicr_id = vm_translate_to_pcpuid(cpu.vcpu->vm, vgicr_id);
        if(pgicr_id != INVALID_CPUID) {
            val = gicr[pgicr_id].ID[((acc->addr & 0xff) - 0xd0) / 4];
        } 
        vcpu_writereg(cpu.vcpu, acc->reg, val);
    }
}

extern struct vgic_reg_handler_info isenabler_info;
extern struct vgic_reg_handler_info ispendr_info;
extern struct vgic_reg_handler_info isactiver_info;
extern struct vgic_reg_handler_info icenabler_info;
extern struct vgic_reg_handler_info icpendr_info;
extern struct vgic_reg_handler_info iactiver_info;
extern struct vgic_reg_handler_info icfgr_info;
extern struct vgic_reg_handler_info ipriorityr_info;
extern struct vgic_reg_handler_info razwi_info;

struct vgic_reg_handler_info irouter_info = {
    vgic_emul_generic_access,
    0b1000,
    VGIC_IROUTER_ID,
    offsetof(struct gicd_hw, IROUTER),
    64,
    vgic_int_get_route,
    vgic_int_set_route,
    vgic_int_set_route_hw,
};

struct vgic_reg_handler_info vgicr_ctrl_info = {
    vgicr_emul_ctrl_access,
    0b0100,
};
struct vgic_reg_handler_info vgicr_typer_info = {
    vgicr_emul_typer_access,
    0b1000,
};
struct vgic_reg_handler_info vgicr_pidr_info = {
    vgicr_emul_pidr_access,
    0b0100,
};

vcpuid_t vgicr_get_id(struct emul_access *acc)
{
    return (acc->addr - cpu.vcpu->vm->arch.vgicr_addr) / sizeof(struct gicr_hw);
}

bool vgicr_emul_handler(struct emul_access *acc)
{
    struct vgic_reg_handler_info *handler_info = NULL;
    switch (GICR_REG_MASK(acc->addr)) {
        case GICR_REG_OFF(CTLR):
            handler_info = &vgicr_ctrl_info;
            break;
        case GICR_REG_OFF(TYPER):
            handler_info = &vgicr_typer_info;
            break;
        case GICR_REG_OFF(ISENABLER0):
            handler_info = &isenabler_info;
            break;
        case GICR_REG_OFF(ISPENDR0):
            handler_info = &ispendr_info;
            break;
        case GICR_REG_OFF(ISACTIVER0):
            handler_info = &iactiver_info;
            break;
        case GICR_REG_OFF(ICENABLER0):
            handler_info = &icenabler_info;
            break;
        case GICR_REG_OFF(ICPENDR0):
            handler_info = &icpendr_info;
            break;
        case GICR_REG_OFF(ICACTIVER0):
            handler_info = &icfgr_info;
            break;
        case GICR_REG_OFF(ICFGR0):
        case GICR_REG_OFF(ICFGR1):
            handler_info = &icfgr_info;
            break;
        default: {
            size_t base_offset = acc->addr - cpu.vcpu->vm->arch.vgicr_addr;
            size_t acc_offset = GICR_REG_MASK(base_offset);
            if (GICR_IS_REG(IPRIORITYR, acc_offset)) {
                handler_info = &ipriorityr_info;
            } else if (GICR_IS_REG(ID, acc_offset)) {
                handler_info = &vgicr_pidr_info;
            } else {
                handler_info = &razwi_info;
            }
        }
    }

    if (vgic_check_reg_alignment(acc, handler_info)) {
        vcpuid_t vgicr_id = vgicr_get_id(acc);
        struct vcpu *vcpu = vgicr_id == cpu.vcpu->id
                           ? cpu.vcpu
                           : vm_get_vcpu(cpu.vcpu->vm, vgicr_id);
        spin_lock(&vcpu->arch.vgic_priv.vgicr.lock);
        handler_info->reg_access(acc, handler_info, true, vgicr_id);
        spin_unlock(&vcpu->arch.vgic_priv.vgicr.lock);
        return true;
    } else {
        return false;
    }
}

bool vgic_icc_sgir_handler(struct emul_access *acc)
{
    if (acc->write) {
        unsigned long sgir = vcpu_readreg(cpu.vcpu, acc->reg);
        irqid_t int_id = ICC_SGIR_SGIINTID(sgir);
        cpumap_t trgtlist;
        if (sgir & ICC_SGIR_IRM_BIT) {
            trgtlist = cpu.vcpu->vm->cpus & ~(1U << cpu.vcpu->phys_id);
        } else {
            /**
             * TODO: we are assuming the vm has a single cluster. Change this
             * when adding virtual cluster support.
             */
            trgtlist = vm_translate_to_pcpu_mask(
                cpu.vcpu->vm, ICC_SGIR_TRGLSTFLT(sgir), cpu.vcpu->vm->cpu_num);
        }
        vgic_send_sgi_msg(cpu.vcpu, trgtlist, int_id);
    }

    return true;
}

bool vgic_icc_sre_handler(struct emul_access *acc)
{
    if (!acc->write) {
        vcpu_writereg(cpu.vcpu, acc->reg, 0x1);
    }
    return true;
}

void vgic_init(struct vm *vm, const struct gic_dscrp *gic_dscrp)
{
    vm->arch.vgicr_addr = gic_dscrp->gicr_addr;
    vm->arch.vgicd.CTLR = 0;
    size_t vtyper_itln = vgic_get_itln(gic_dscrp);
    vm->arch.vgicd.int_num = 32 * (vtyper_itln + 1);
    vm->arch.vgicd.TYPER =
        ((vtyper_itln << GICD_TYPER_ITLN_OFF) & GICD_TYPER_ITLN_MSK) |
        (((vm->cpu_num - 1) << GICD_TYPER_CPUNUM_OFF) & GICD_TYPER_CPUNUM_MSK) |
        (((10 - 1) << GICD_TYPER_IDBITS_OFF) & GICD_TYPER_IDBITS_MSK);
    vm->arch.vgicd.IIDR = gicd.IIDR;

    size_t vgic_int_size = vm->arch.vgicd.int_num * sizeof(struct vgic_int);
    vm->arch.vgicd.interrupts =
        mem_alloc_page(NUM_PAGES(vgic_int_size), SEC_HYP_VM, false);
    if (vm->arch.vgicd.interrupts == NULL) {
        ERROR("failed to alloc vgic");
    }

    for (size_t i = 0; i < vm->arch.vgicd.int_num; i++) {
        vm->arch.vgicd.interrupts[i].owner = NULL;
        vm->arch.vgicd.interrupts[i].lock = SPINLOCK_INITVAL;
        vm->arch.vgicd.interrupts[i].id = i + GIC_CPU_PRIV;
        vm->arch.vgicd.interrupts[i].state = INV;
        vm->arch.vgicd.interrupts[i].prio = GIC_LOWEST_PRIO;
        vm->arch.vgicd.interrupts[i].cfg = 0;
        vm->arch.vgicd.interrupts[i].route = GICD_IROUTER_INV;
        vm->arch.vgicd.interrupts[i].phys.route = GICD_IROUTER_INV;
        vm->arch.vgicd.interrupts[i].hw = false;
        vm->arch.vgicd.interrupts[i].in_lr = false;
        vm->arch.vgicd.interrupts[i].enabled = false;
    }

    struct emul_mem gicd_emu = {.va_base = gic_dscrp->gicd_addr,
                           .size = ALIGN(sizeof(struct gicd_hw), PAGE_SIZE),
                           .handler = vgicd_emul_handler};
    vm_emul_add_mem(vm, &gicd_emu);

    list_foreach(vm->vcpu_list, struct node_data, node){
	struct vcpu* vcpu = node->data;
        struct emul_mem gicr_emu = {
            .va_base = gic_dscrp->gicr_addr + sizeof(struct gicr_hw) * vcpu->id,
            .size = ALIGN(sizeof(struct gicr_hw), PAGE_SIZE),
            .handler = vgicr_emul_handler};
        vm_emul_add_mem(vm, &gicr_emu);

        vcpu->arch.vgic_priv.vgicr.CTLR = 0;

        uint64_t typer = (uint64_t)vcpu->id << GICR_TYPER_PRCNUM_OFF;
        typer |= (vcpu->arch.vmpidr & MPIDR_AFF_MSK) << GICR_TYPER_AFFVAL_OFF;
        typer |= !!(vcpu->id == vcpu->vm->cpu_num - 1) << GICR_TYPER_LAST_OFF;
        vcpu->arch.vgic_priv.vgicr.TYPER = typer;

        vcpu->arch.vgic_priv.vgicr.IIDR = gicr[cpu.id].IIDR;
    }

    struct emul_reg icc_sgir_emu = {.addr = SYSREG_ENC_ADDR(3, 0, 12, 11, 5),
                               .handler = vgic_icc_sgir_handler};
    vm_emul_add_reg(vm, &icc_sgir_emu);

    struct emul_reg icc_sre_emu = {.addr = SYSREG_ENC_ADDR(3, 0, 12, 12, 5),
                              .handler = vgic_icc_sre_handler};
    vm_emul_add_reg(vm, &icc_sre_emu);

    list_init(&vm->arch.vgic_spilled);
    vm->arch.vgic_spilled_lock = SPINLOCK_INITVAL;
}

void vgic_cpu_init(struct vcpu *vcpu)
{
    for (size_t i = 0; i < GIC_CPU_PRIV; i++) {
        vcpu->arch.vgic_priv.interrupts[i].owner = NULL;
        vcpu->arch.vgic_priv.interrupts[i].lock = SPINLOCK_INITVAL;
        vcpu->arch.vgic_priv.interrupts[i].id = i;
        vcpu->arch.vgic_priv.interrupts[i].state = INV;
        vcpu->arch.vgic_priv.interrupts[i].prio = GIC_LOWEST_PRIO;
        vcpu->arch.vgic_priv.interrupts[i].cfg = 0;
        vcpu->arch.vgic_priv.interrupts[i].route = GICD_IROUTER_INV;
        vcpu->arch.vgic_priv.interrupts[i].phys.redist = vcpu->phys_id;                              
        vcpu->arch.vgic_priv.interrupts[i].hw = false;
        vcpu->arch.vgic_priv.interrupts[i].in_lr = false;
        vcpu->arch.vgic_priv.interrupts[i].enabled = false;
    }

    for (size_t i = 0; i < GIC_MAX_SGIS; i++) {
        vcpu->arch.vgic_priv.interrupts[i].cfg = 0b10;
    }

    list_init(&vcpu->arch.vgic_spilled);
}
