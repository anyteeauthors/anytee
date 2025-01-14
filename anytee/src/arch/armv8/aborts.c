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

#include <arch/aborts.h>
#include <arch/sysregs.h>
#include <cpu.h>
#include <vm.h>
#include <emul.h>
#include <arch/psci.h>
#include <hypercall.h>
#include <arch/smc.h>

/** hypercall handler declarations */
#include <ipc.h>
#include <vmstack.h>
#include <vmm.h>

typedef void (*abort_handler_t)(uint64_t, uint64_t, uint64_t);

void internal_abort_handler(uint64_t gprs[]) {

    for(size_t i = 0; i < 31; i++) {
        printk("x%d:\t\t0x%0lx\n", i, gprs[i]);
    }
    printk("SP_EL2:\t\t0x%0lx\n", gprs[32]);
    printk("ESR_EL2:\t0x%0lx\n", MRS(ESR_EL2));
    printk("ELR_EL2:\t0x%0lx\n", MRS(ELR_EL2));
    printk("FAR_EL2:\t0x%0lx\n", MRS(FAR_EL2));
    ERROR("cpu%d internal hypervisor abort - PANIC\n", cpu.id);
}

void aborts_data_lower(uint64_t iss, uint64_t far, uint64_t il)
{
    if (!(iss & ESR_ISS_DA_ISV_BIT) || (iss & ESR_ISS_DA_FnV_BIT)) {
        ERROR("no information to handle data abort (0x%x)", far);
    }

    uint64_t DSFC =
        bit64_extract(iss, ESR_ISS_DA_DSFC_OFF, ESR_ISS_DA_DSFC_LEN) & (0xf << 2);

    if (DSFC != ESR_ISS_DA_DSFC_TRNSLT) {
        ERROR("data abort is not translation fault - cant deal with it");
    }

    vaddr_t addr = far;
    emul_handler_t handler = vm_emul_get_mem(cpu.vcpu->vm, addr);
    if (handler != NULL) {
        struct emul_access emul;
        emul.addr = addr;
        emul.width =
            (1 << bit64_extract(iss, ESR_ISS_DA_SAS_OFF, ESR_ISS_DA_SAS_LEN));
        emul.write = iss & ESR_ISS_DA_WnR_BIT ? true : false;
        emul.reg = bit64_extract(iss, ESR_ISS_DA_SRT_OFF, ESR_ISS_DA_SRT_LEN);
        emul.reg_width =
            4 + (4 * bit64_extract(iss, ESR_ISS_DA_SF_OFF, ESR_ISS_DA_SF_LEN));
        emul.sign_ext =
            bit64_extract(iss, ESR_ISS_DA_SSE_OFF, ESR_ISS_DA_SSE_LEN);

        // TODO: check if the access is aligned. If not, inject an exception in
        // the vm
        if (handler(&emul)) {
            uint64_t pc_step = 2 + (2 * il);
            vcpu_writepc(cpu.vcpu, vcpu_readpc(cpu.vcpu) + pc_step);
        } else {
            ERROR("data abort emulation failed (0x%x)", far);
        }
    } else {
        struct vcpu* vcpu = cpu.vcpu;
        list_foreach(vcpu->vm->mem_abort_list, struct hndl_mem_abort_node, node)
        {
            mem_abort_handler_t handler = node->hndl_mem_abort.handler;
            if (handler != NULL) {
                if (handler(vcpu, addr)) {
                    ERROR("handler smc failed (0x%x)", far);
                }
            }
        }
    }
}

void smc64_handler(uint64_t iss, uint64_t far, uint64_t il)
{
    uint64_t smc_fid = cpu.vcpu->regs->x[0];

    struct vcpu* vcpu = cpu.vcpu;


    list_foreach(vcpu->vm->smc_list, struct hndl_smc_node, node)
    {
        /* TODO: match range */
        smc_handler_t handler = node->hndl_smc.handler;
        if (handler != NULL) {
            if (handler(vcpu, smc_fid)) {
                ERROR("handler smc failed (0x%x)", far);
            }
        }
    }
}

void hvc64_handler(uint64_t iss, uint64_t far, uint64_t il)
{
    uint64_t x0 = cpu.vcpu->regs->x[0];

    struct vcpu* vcpu = cpu.vcpu;

    list_foreach(vcpu->vm->hvc_list, struct hndl_hvc_node, node)
    {
        /* TODO: match range */
        hvc_handler_t handler = node->hndl_hvc.handler;
        if (handler != NULL) {
            if (handler(vcpu, x0 & 0xffff)) {
                ERROR("handler hvc failed (0x%x)", far);
            }
        }
    }
}

void sysreg_handler(uint64_t iss, uint64_t far, uint64_t il)
{
    vaddr_t reg_addr = iss & ESR_ISS_SYSREG_ADDR;
    emul_handler_t handler = vm_emul_get_reg(cpu.vcpu->vm, reg_addr);
    if(handler != NULL){
        struct emul_access emul;
        emul.addr = reg_addr;
        emul.width = 8;
        emul.write = iss & ESR_ISS_SYSREG_DIR ? false : true;
        emul.reg = bit64_extract(iss, ESR_ISS_SYSREG_REG_OFF, ESR_ISS_SYSREG_REG_LEN);
        emul.reg_width = 8;
        emul.sign_ext = false;

        if (handler(&emul)) {
            uint64_t pc_step = 2 + (2 * il);
            vcpu_writepc(cpu.vcpu, vcpu_readpc(cpu.vcpu) + pc_step);
        } else {
            ERROR("register access emulation failed (0x%x)", reg_addr);
        }
    } else {
        ERROR("no emulation handler for register access (0x%x at 0x%x)",
              reg_addr, vcpu_readpc(cpu.vcpu));
    }
}

abort_handler_t abort_handlers[64] = {[ESR_EC_DALEL] = aborts_data_lower,
                                      [ESR_EC_SMC64] = smc64_handler,
                                      [ESR_EC_SYSRG] = sysreg_handler,
                                      [ESR_EC_HVC64] = hvc64_handler};

void aborts_sync_handler()
{
    uint64_t esr = MRS(ESR_EL2);
    uint64_t far = MRS(FAR_EL2);
    uint64_t hpfar = MRS(HPFAR_EL2);
    uint64_t ipa_fault_addr = 0;

    ipa_fault_addr = (far & 0xFFF) | (hpfar << 8);

    uint64_t ec = bit64_extract(esr, ESR_EC_OFF, ESR_EC_LEN);
    uint64_t il = bit64_extract(esr, ESR_IL_OFF, ESR_IL_LEN);
    uint64_t iss = bit64_extract(esr, ESR_ISS_OFF, ESR_ISS_LEN);

    abort_handler_t handler = abort_handlers[ec];
    if (handler)
        handler(iss, ipa_fault_addr, il);
    else
        ERROR("no handler for abort ec = 0x%x iss: 0x%x", ec, iss);  // unknown guest exception
}
