/** 
 * Bao, a Lightweight Static Partitioning Hypervisor 
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      David Cerdeira <davidmcerdeira@gmail.com>
 *      Jose Martins <jose.martins@bao-project.org>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details. 
 *
 */

#include <arch/psci.h>
#include <arch/smc.h>
#include <arch/sysregs.h>
#include <fences.h>
#include <page_table.h>
#include <vm.h>
#include <cpu.h>
#include <objcache.h>
#include <mem.h>
#include <cache.h>
#include <vmstack.h>

enum {PSCI_MSG_ON};

extern void psci_boot_entry(unsigned long x0);

/* --------------------------------
	SMC Trapping
--------------------------------- */

void psci_wake_from_off(uint64_t vmid){
  
    struct vcpu *vcpu = cpu_get_vcpu(vmid);

    if(cpu.vcpu == NULL){   
        return;
    }

    /* update vcpu.psci_ctx */
    spin_lock(&cpu.vcpu->arch.psci_ctx.lock);
    if(cpu.vcpu->arch.psci_ctx.state == ON_PENDING){
        vcpu_arch_reset(cpu.vcpu, cpu.vcpu->arch.psci_ctx.entrypoint);
        if(vcpu == cpu.vcpu) vcpu_restore_state(cpu.vcpu);
        cpu.vcpu->arch.psci_ctx.state = ON;
        cpu.vcpu->regs->x[0] = cpu.vcpu->arch.psci_ctx.context_id;
    }
    spin_unlock(&cpu.vcpu->arch.psci_ctx.lock);
}

void psci_cpumsg_handler(uint32_t event, uint64_t data){

    switch(event){
        case PSCI_MSG_ON:
            psci_wake_from_off(data);
        break;
    }
}

CPU_MSG_HANDLER(psci_cpumsg_handler, PSCI_CPUSMG_ID);

int32_t psci_cpu_suspend_handler(uint32_t power_state, unsigned long entrypoint, 
                                                    unsigned long context_id)
{
    /**
     * !! Ignoring the rest of the requested  powerstate for now. 
     * This might be a problem howwver since powerlevel and stateid are 
     * implementation defined.
     */ 
    uint32_t state_type = power_state & PSCI_STATE_TYPE_BIT;
    int32_t ret;
    /* struct vcpu* vcpu = cpu.vcpu; */

    if(state_type){
        //PSCI_STATE_TYPE_POWERDOWN:
        spin_lock(&cpu.vcpu->arch.psci_ctx.lock);
        cpu.vcpu->arch.psci_ctx.entrypoint = entrypoint;
        cpu.vcpu->arch.psci_ctx.context_id = context_id;
        spin_unlock(&cpu.vcpu->arch.psci_ctx.lock);
        if(vmstack_pop() == NULL){
            ret = psci_power_down(PSCI_WAKEUP_POWERDOWN);
        } else {
            ret = PSCI_E_SUCCESS;
        }
    } else {
        //PSCI_STATE_TYPE_STANDBY:
        /**
         *  TODO: ideally we would emmit a standby request to PSCI 
         * (currently, ATF), but when we do, we do not wake up on interrupts
         * on the current development target zcu104.
         * We should understand why. To circunvent this, we directly emmit a
         * wfi 
         */
        //ret = psci_standby();
        if(vmstack_pop() == NULL){
            asm volatile("wfi\n\r");
        }
        ret = PSCI_E_SUCCESS;
    }

    return ret;
}


int32_t psci_cpu_off_handler(void)
{
    /**
     *  Right now we only support one vcpu por cpu, so passthrough the request
     *  directly to the monitor psci implementation. Later another vcpu, will
     *  call cpu_on on this vcpu. 
     */

    spin_lock(&cpu.vcpu->arch.psci_ctx.lock);
    cpu.vcpu->arch.psci_ctx.state = OFF;
    cpu.vcpu->state = VCPU_OFF;
    spin_unlock(&cpu.vcpu->arch.psci_ctx.lock);

    if(vmstack_pop() == NULL){
        cpu_idle();

        spin_lock(&cpu.vcpu->arch.psci_ctx.lock);
        cpu.vcpu->arch.psci_ctx.state = ON;
        cpu.vcpu->state = VCPU_ACTIVE;
        spin_unlock(&cpu.vcpu->arch.psci_ctx.lock);

        return PSCI_E_DENIED;
    }
    return PSCI_E_SUCCESS;
}

int32_t psci_cpu_on_handler(unsigned long target_cpu, unsigned long entrypoint,
                            unsigned long context_id)
{
    int32_t ret;
    struct vm* vm = cpu.vcpu->vm;
    struct vcpu* target_vcpu = vm_get_vcpu_by_mpidr(vm, target_cpu);

    if (target_vcpu != NULL){

        bool already_on = true;
        spin_lock(&cpu.vcpu->arch.psci_ctx.lock);
        if(target_vcpu->arch.psci_ctx.state == OFF){
            /* TODO target_vcpu->arch.psci_ctx.state = ON_PENDING; */
            target_vcpu->arch.psci_ctx.entrypoint = entrypoint;
            target_vcpu->arch.psci_ctx.context_id = context_id;
            fence_sync_write();
            already_on = false;
        } 
        spin_unlock(&cpu.vcpu->arch.psci_ctx.lock);

        if(already_on){
            return PSCI_E_ALREADY_ON;
        }

        cpuid_t pcpuid = vm_translate_to_pcpuid(vm, target_vcpu->id);
        if (pcpuid == INVALID_CPUID) {
            ret = PSCI_E_INVALID_PARAMS;
        } else {
            struct cpu_msg msg = {PSCI_CPUSMG_ID, PSCI_MSG_ON};
            cpu_send_msg(pcpuid, &msg);
            ret = PSCI_E_SUCCESS;
        }

    } else {
        ret = PSCI_E_INVALID_PARAMS;
    }

    return ret;
}


int32_t psci_affinity_info_handler(unsigned long  target_affinity, 
                                uint32_t lowest_affinity_level)
{
    /* return ON, if at least one core in the affinity instance: has been 
    enabled with a call to CPU_ON, and that core has not called CPU_OFF */

    /* return off if all of the cores in the affinity instance have called 
    CPU_OFF and each of these calls has been processed by the PSCI 
    implementation. */

    /*  return ON_PENDING if at least one core in the affinity instance is in 
    the ON_PENDING state */

    /**
     * TODO
     */

    return 0;
}

int32_t psci_features_handler(uint32_t feature_id){

    int32_t ret = PSCI_E_NOT_SUPPORTED;

    switch (feature_id) {
        case PSCI_VERSION:
        case PSCI_CPU_OFF:
        case PSCI_CPU_SUSPEND_AARCH64:
        case PSCI_CPU_ON_AARCH64:
        case PSCI_AFFINITY_INFO_AARCH32:
        case PSCI_FEATURES:
            ret = PSCI_E_SUCCESS;
            break;
    }    

    return ret;
}


int32_t psci_smc_handler(uint32_t smc_fid, unsigned long x1, unsigned long x2, 
                        unsigned long x3)
{
   int32_t ret = PSCI_E_NOT_SUPPORTED;

    switch (smc_fid) {
		case PSCI_VERSION:
			ret = psci_version();
			break;

		case PSCI_CPU_OFF:
			ret = psci_cpu_off_handler();
			break;

		case PSCI_CPU_SUSPEND_AARCH64:
			ret = psci_cpu_suspend_handler(x1, x2, x3);
			break;

		case PSCI_CPU_ON_AARCH64:
			ret = psci_cpu_on_handler(x1, x2, x3);
			break;

		case PSCI_AFFINITY_INFO_AARCH64:
			ret = psci_affinity_info_handler(x1, x2);
			break;

        case PSCI_FEATURES:
			ret = psci_features_handler(x1);
			break;

        case PSCI_MIG_INFO_TYPE:
            ret = PSCI_TOS_NOT_PRESENT_MP;
            break;

        default:
            INFO("unkown psci smc_fid 0x%lx", smc_fid);
   }

    return ret;
}

extern uint8_t root_l1_flat_pt;

static void psci_save_state(enum wakeup_reason wakeup_reason){

    cpu.arch.psci_off_state.tcr_el2 = MRS(TCR_EL2);
    cpu.arch.psci_off_state.ttbr0_el2 = MRS(TTBR0_EL2);
    cpu.arch.psci_off_state.mair_el2 = MRS(MAIR_EL2);
    cpu.arch.psci_off_state.cptr_el2 = MRS(CPTR_EL2);
    cpu.arch.psci_off_state.hcr_el2 = MRS(HCR_EL2);
    cpu.arch.psci_off_state.vmpidr_el2 = MRS(VMPIDR_EL2);
    cpu.arch.psci_off_state.vtcr_el2 = MRS(VTCR_EL2);
    cpu.arch.psci_off_state.vttbr_el2 = MRS(VTTBR_EL2);
    mem_translate(&cpu.as, (vaddr_t)&root_l1_flat_pt,
                    &cpu.arch.psci_off_state.flat_map);
    cpu.arch.psci_off_state.wakeup_reason = wakeup_reason;

    /**
     * Although the real PSCI implementation is responsible for managing cache
     * state, make sure the saved state is in memory as we'll use this on wake
     * up before enabling cache to restore basic processor state. 
     */
    cache_flush_range((vaddr_t)&cpu.arch.psci_off_state,
                    sizeof(cpu.arch.psci_off_state));

    gicc_save_state(&cpu.arch.psci_off_state.gicc_state);
    vcpu_save_state(cpu.vcpu);
}


static void psci_restore_state(){

    /**
     * The majority of the state is already restored in assembly routine
     *  psci_boot_entry.
     */
    
    gicc_restore_state(&cpu.arch.psci_off_state.gicc_state);
    vcpu_restore_state(cpu.vcpu);
}

void psci_wake_from_powerdown(uint64_t vmid){

    if(cpu.vcpu == NULL){
        ERROR("cpu woke up but theres no vcpu to run");
    }

    vcpu_arch_reset(cpu.vcpu, cpu.vcpu->arch.psci_ctx.entrypoint);
    vcpu_writereg(cpu.vcpu, 0, cpu.vcpu->arch.psci_ctx.context_id);
    vcpu_run(cpu.vcpu);
}

void psci_wake_from_idle(uint64_t vmid){

    cpu_idle_wakeup();

}

void (*psci_wake_handlers[PSCI_WAKEUP_NUM])(uint64_t vmid) = {
    [PSCI_WAKEUP_CPU_OFF] = psci_wake_from_off,
    [PSCI_WAKEUP_POWERDOWN] = psci_wake_from_powerdown,
    [PSCI_WAKEUP_IDLE] = psci_wake_from_idle,
};

void psci_wake(uint32_t handler_id)
{    

    psci_restore_state();

    if(handler_id < PSCI_WAKEUP_NUM){
        psci_wake_handlers[handler_id](0U);
    } else {
        ERROR("unkown reason for cpu wake up");
    }

}

int32_t psci_standby(){
    /* only apply request to core level */
    uint32_t pwr_state_aux = PSCI_POWER_STATE_LVL_0 | PSCI_STATE_TYPE_STANDBY;

    return psci_cpu_suspend(pwr_state_aux, 0, 0);
}

int32_t psci_power_down(enum wakeup_reason reason){

    uint32_t pwr_state_aux = PSCI_POWER_STATE_LVL_0 | PSCI_STATE_TYPE_POWERDOWN;

    psci_save_state(reason);
    paddr_t cntxt_paddr;
    paddr_t psci_wakeup_addr;
    mem_translate(&cpu.as, (vaddr_t)&cpu.arch.psci_off_state, &cntxt_paddr);
    mem_translate(&cpu.as, (vaddr_t)&psci_boot_entry, &psci_wakeup_addr);

    return psci_cpu_suspend(pwr_state_aux, psci_wakeup_addr, cntxt_paddr);
}

/* --------------------------------
    SMC PSCI interface 
--------------------------------- */

int32_t psci_version(void)
{
    return smc_call(PSCI_VERSION, 0, 0, 0, NULL);
}


int32_t psci_cpu_suspend(uint32_t power_state, unsigned long entrypoint, 
                        unsigned long context_id)
{

    return smc_call(PSCI_CPU_SUSPEND_AARCH64, power_state, entrypoint, 
                                                            context_id, NULL);
}

int32_t psci_cpu_off(void)
{   
    return smc_call(PSCI_CPU_OFF, 0, 0, 0, NULL);
}

int32_t psci_cpu_on(unsigned long target_cpu, unsigned long entrypoint, 
                    unsigned long context_id)
{
    return smc_call(PSCI_CPU_ON_AARCH64, target_cpu, entrypoint, context_id,
                                                                        NULL);
}

int32_t psci_affinity_info(unsigned long target_affinity, 
                            uint32_t lowest_affinity_level)
{
    return smc_call(PSCI_AFFINITY_INFO_AARCH64, target_affinity, 
                                            lowest_affinity_level, 0, NULL);
}
