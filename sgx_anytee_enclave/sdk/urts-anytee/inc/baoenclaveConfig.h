#ifndef __CONFIG__
#include <stdint.h> // uintptr_t
#include <stdlib.h> // size_t
#endif              //__CONFIG__

#include <stdbool.h>


#define adjust_ptr(p, o) \
    ((p) = (p) ? (typeof(p))((void *)(p) + (uint64_t)(o)) : (p))

typedef signed long ssize_t;

typedef unsigned long asid_t;

typedef unsigned long vmid_t;

typedef uintptr_t paddr_t;
typedef uintptr_t vaddr_t;
#define NULL_VA ((vaddr_t)NULL)
#define MAX_VA  ((vaddr_t)-1)

typedef unsigned long colormap_t;

typedef unsigned long cpuid_t;
typedef unsigned long vcpuid_t;
typedef unsigned long cpumap_t;
#define INVALID_CPUID   ((cpuid_t)-1)

typedef unsigned irqid_t;

typedef unsigned streamid_t;

struct mem_region
{
    uint64_t base;
    size_t size;
    uint64_t colors;
    bool place_phys;
    uint64_t phys;
};

struct arch_platform
{
    struct
    {
        uint64_t base;
        uint64_t interrupt_id;
        uint16_t global_mask;

        uint32_t group_num;
        struct smmu_group
        {
            uint16_t group_mask;
            uint16_t group_id;
        } * smmu_groups;

    } smmu;
};

typedef struct ipc
{
    uint64_t base;
    size_t size;
    uint64_t shmem_id;
    size_t interrupt_num;
    uint64_t *interrupts;
} ipc_t;

struct dev_region
{
    uint64_t pa;
    uint64_t va;
    size_t size;
    size_t interrupt_num;
    uint64_t *interrupts;
    uint32_t id; /* bus master id for iommu effects */
};

struct platform_desc
{
    uint64_t cpu_num;

    uint64_t region_num;
    struct mem_region *regions;

    uint64_t ipc_num;
    struct ipc *ipcs;

    uint64_t dev_num;
    struct dev_region *devs;

    struct
    {
        uint64_t base;
    } console;

    struct arch_platform arch;
};
struct fdt_header
{
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};

typedef struct shmem
{
    uint64_t size;
    uint64_t colors;
    bool place_phys;
    uint64_t phys;
    uint64_t cpu_masters;
} shmem_t;


struct vm_config {
    struct {
        /* Image load address in VM's address space */
        vaddr_t base_addr;
        /* Image load address in hyp address space */
        paddr_t load_addr;
        /* Image size */
        size_t size;
        /* Dont copy the image */
        bool inplace;
    } image;

    /* Entry point address in VM's address space */
    vaddr_t entry;
    /**
     * A bitmap signaling the preferred physical cpus assigned to the VM.
     * If this value is each mutual exclusive for all the VMs, this field
     * allows to direcly assign specific physical cpus to the VM.
     */
    cpumap_t cpu_affinity;

    /**
     * A bitmap for the assigned colors of the VM. This value is truncated
     * depending on the number of available colors calculated at runtime
     */
    colormap_t colors;
    size_t children_num;
    struct vm_config **children;

    /**
     * A description of the virtual platform available to the guest, i.e.,
     * the virtual machine itself.
     */

    // --- SDSGX --- //
    uint64_t alloc_vm;

    struct platform_desc platform;

};

struct config {
    /**
     *  Faking the fdt header allows to boot using u-boot mechanisms passing
     * this configuration as the dtb.
     */
    struct fdt_header fdt_header;

    /* The of this struct aligned to page size */
    size_t config_header_size;
    /* The size of the full configuration binary, including VM images */
    size_t config_size;

    /* Hypervisor colors */
    colormap_t hyp_colors;

    /* Definition of shared memory regions to be used by VMs */
    size_t shmemlist_size;
    struct shmem *shmemlist;

    /* The number of VMs specified by this configuration */
    size_t vmlist_size;

    /* Array list with VM configuration */
    struct vm_config *vmlist[];
};

//size of à estrutura e copio estes bytes para saber o tamanho, depois copiar tudo
