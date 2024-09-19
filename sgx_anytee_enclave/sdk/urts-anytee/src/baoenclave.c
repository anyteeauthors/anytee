#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>

#include "contiguousMalloc.h"
#include "sdsgx.h"
#include "sdsgxConfig.h"


void print_shmem(shmem_t *shmem) {
  printf("            size: %lx\n", shmem->size);
  printf("            colors: %lx\n", shmem->colors);
  printf("            place_phys: %x\n", shmem->place_phys);
  printf("            phys: %lx\n", shmem->phys);
  printf("            cpu_masters: %lx\n", shmem->cpu_masters);
}

void print_mem_region(struct mem_region *region) {
  printf("          base: %lx\n", region->base);
  printf("          size: %zx\n", region->size);
  printf("          colors: %lx\n", region->colors);
  printf("          place_phys: %x\n", region->place_phys);
  printf("          phys: %lx\n", region->phys);
}

void print_ipc(struct ipc *ipc) {
  printf("          base: %lx\n", ipc->base);
  printf("          size: %zx\n", ipc->size);
  printf("          shmem_id: %lx\n", ipc->shmem_id);
  printf("          interrupt_num: %zx\n", ipc->interrupt_num);
  printf("          interrupts:\n");
  for (size_t i = 0; i < ipc->interrupt_num; i++) {
    printf("      %lx\n", ipc->interrupts[i]);
  }
}

void print_dev_region(struct dev_region *dev) {
  printf("          pa: %lx\n", dev->pa);
  printf("          va: %lx\n", dev->va);
  printf("          size: %zx\n", dev->size);
  printf("          interrupt_num: %zx\n", dev->interrupt_num);
  printf("          interrupts:\n");
  for (size_t i = 0; i < dev->interrupt_num; i++) {
    printf("      %lx\n", dev->interrupts[i]);
  }
  printf("    id: %x\n", dev->id);
}

void print_vm_config(struct vm_config *vm_config) {
  printf("    VM Config:\n");
  printf("      Image:\n");
  printf("        base_addr: %lx\n", vm_config->image.base_addr);
  printf("        load_addr: %lx\n", vm_config->image.load_addr);
  printf("        size: %zx\n", vm_config->image.size);
  printf("      Entry: %lx\n", vm_config->entry);
  printf("      CPU affinity: %lx\n", vm_config->cpu_affinity);
  printf("      Colors: %lx\n", vm_config->colors);
  printf("      Alloc VM: %lx\n", vm_config->alloc_vm);
  printf("      Platform:\n");
  printf("        CPU num: %lx\n", vm_config->platform.cpu_num);
  printf("        Region num: %lx\n", vm_config->platform.region_num);
  print_mem_region(vm_config->platform.regions);
  printf("        IPC num: %lx\n", vm_config->platform.ipc_num);
  print_ipc(vm_config->platform.ipcs);
  printf("        Dev num: %lx\n", vm_config->platform.dev_num);
  print_dev_region(vm_config->platform.devs);
  printf("        Console:\n");
  printf("          base: %lx\n", vm_config->platform.console.base);
  printf("        Arch:\n");
  printf("          SMMU:\n");
  printf("            base: %lx\n", vm_config->platform.arch.smmu.base);
  printf("            interrupt_id: %lx\n", vm_config->platform.arch.smmu.interrupt_id);
  printf("            global_mask: %x\n", vm_config->platform.arch.smmu.global_mask);
  printf("            group_num: %x\n", vm_config->platform.arch.smmu.group_num);
  printf("            smmu_groups:\n");
  for (uint32_t i = 0; i < vm_config->platform.arch.smmu.group_num; i++) {
    printf("              group_mask: %x\n", vm_config->platform.arch.smmu.smmu_groups[i].group_mask);
    printf("              group_id: %x\n", vm_config->platform.arch.smmu.smmu_groups[i].group_id);
  }
  printf("      Number of children: %zx\n", vm_config->children_num);
}


void print_config(struct config *config) {
  printf("Config:\n");
  printf("  FDT Header:\n");
  printf("    magic: %x\n", config->fdt_header.magic);
  printf("    totalsize: %x\n", config->fdt_header.totalsize);
  printf("    off_dt_struct: %x\n", config->fdt_header.off_dt_struct);
  printf("    off_dt_strings: %x\n", config->fdt_header.off_dt_strings);
  printf("    off_mem_rsvmap: %x\n", config->fdt_header.off_mem_rsvmap);
  printf("    version: %x\n", config->fdt_header.version);
  printf("    last_comp_version: %x\n", config->fdt_header.last_comp_version);
  printf("    boot_cpuid_phys: %x\n", config->fdt_header.boot_cpuid_phys);
  printf("    size_dt_strings: %x\n", config->fdt_header.size_dt_strings);
  printf("    size_dt_struct: %x\n", config->fdt_header.size_dt_struct);
  printf("  Config header size: %zx\n", config->config_header_size);
  printf("  Config size: %zx\n", config->config_size);
  printf("  Hyp colors: %lx\n", config->hyp_colors);
  printf("  Shmem list size: %zx\n", config->shmemlist_size);
  printf("  Shmem list:\n");
  for (size_t i = 0; i < config->shmemlist_size; i++) {
    printf("    Shmem %zx:\n", i);
    print_shmem(&config->shmemlist[i]);
  }
  printf("  VM list size: %zx\n", config->vmlist_size);
  printf("  VM list:\n");
  for (size_t i = 0; i < config->vmlist_size; i++) {
    printf("    VM %zx:\n", i);
    print_vm_config(config->vmlist[i]);
  }
}


extern uint8_t _sdsgx_shmem;

static uint64_t sdsgx_hvc(uint64_t fid, uint64_t x1, uint64_t x2,
    uint64_t x3)
{
    register uint64_t r0 asm("x0") = fid;
    register uint64_t r1 asm("x1") = x1;
    register uint64_t r2 asm("x2") = x2;
    register uint64_t r3 asm("x3") = x3;

    asm volatile("hvc	#0\n"
		 : "=r"(r0)
		 : "r"(r0), "r"(r1), "r"(r2), "r"(r3));

    return r0;
}


void config_arch_vm_adjust_to_va(struct vm_config *vm_config, struct config *config, uint64_t phys)
{
    for (int i = 0; i < config->vmlist_size; i++)
    {
        adjust_ptr(vm_config->platform.arch.smmu.smmu_groups, config);
    }
}

void config_vm_adjust_to_va(struct vm_config *vm_config, struct config *config,
                            uint64_t phys)
{
    config_arch_vm_adjust_to_va(vm_config, config, phys);

    for (int i = 0; i < config->vmlist_size; i++) {
        adjust_ptr(vm_config->image.load_addr, phys);

        adjust_ptr(vm_config->platform.regions, config);

        if (adjust_ptr(vm_config->platform.devs, config)) {
            for (int j = 0; j < vm_config->platform.dev_num; j++) {
                adjust_ptr(vm_config->platform.devs[j].interrupts, config);
            }
        }

        if (adjust_ptr(vm_config->platform.ipcs, config)) {
            for (int j = 0; j < vm_config->platform.ipc_num; j++) {
                adjust_ptr(vm_config->platform.ipcs[j].interrupts, config);
            }
        }

        adjust_ptr(vm_config->children, config);
        for (int i = 0; i < vm_config->children_num; i++) {
            adjust_ptr(vm_config->children[i], config);
            config_vm_adjust_to_va(vm_config->children[i], config, phys);
        }
    }
}

void config_adjust_to_va(struct config *config, uint64_t phys)
{
    adjust_ptr(config->shmemlist, config);
    for (int i = 0; i < config->vmlist_size; i++)
    {
	adjust_ptr(config->vmlist[i], config);
        config_vm_adjust_to_va(config->vmlist[i], config, phys);
    }
}

void* sdsgx_alloc_space(size_t size, uintptr_t* phys_addr)
{
    void *userspace = mallocContiguous(size, phys_addr);
    if (userspace == NULL)
    {
        printf("(APP) Failed to aquire memory!\n");
    }
    memset(userspace, 0, size);

    return userspace;
}

void sdsgx_free_space(size_t size, uintptr_t phys_addr, void* userspace)
{
if (freeContiguous(phys_addr, userspace, size) != 0)
    {
        printf("Failed to free memory!\n");
    }
}

void sdsgx_place_config(char * filename, uintptr_t* phys_addr, void** userspace,
                             size_t* full_size, size_t* shmem_size)
{
    FILE *fptr = NULL;
    size_t reqSize;
    struct config cfg;

    fptr = fopen(filename, "rb");
    if (fptr == NULL)
    {
        perror("Could not open file");
        exit(EXIT_FAILURE);
    }

    fread(&cfg, sizeof(struct config), 1, fptr);

    reqSize = cfg.config_size;

    *userspace = malloc(reqSize);

    fseek(fptr, 0, SEEK_SET);
    fread(*userspace, reqSize, 1, fptr);

    struct config *config_ptr;
    config_ptr = (struct config *)(uint64_t)*userspace;

    config_adjust_to_va(config_ptr, (uint64_t)*userspace);
    /* print_config(config_ptr); */

    /* TODO use dynamic shared memory, we are using the bao driver allocate memory */
    //*shmem_size = config_ptr->vmlist[0]->platform.ipcs->size;
    *full_size = (size_t)(config_ptr->vmlist[0]->platform.regions[0].size + config_ptr->config_header_size);// + *shmem_size);

    *userspace = sdsgx_alloc_space(*full_size, phys_addr);

    fseek(fptr, 0, SEEK_SET);
    fread(*userspace, reqSize, 1, fptr);
    fclose(fptr);
}

void sdsgx_exit()
{
    sdsgx_hvc(0x30003, 0, 0, 0);
}
