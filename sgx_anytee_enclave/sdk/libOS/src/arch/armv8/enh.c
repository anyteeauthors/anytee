#include <stdint.h>
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <page_tables.h>

void *mmap(void *addr, size_t length, int prot, int flags, int fd, size_t offset)
{
    return (void*)0x80000000;
    /* unsigned perm = 0; */
    /* void* result = malloc(length); */

    /* if(!result) */
	/* return NULL; */

    /* return result; */
}

int munmap(void *addr, size_t length)
{
    return 0;
}

size_t getpagesize()
{
    return 0x200000;
}

unsigned long pkey_map = {0};

extern unsigned long *root_page_table;
extern unsigned long *root_page_table_1nwA;
extern unsigned long *root_page_table_1nA;

void enforce_pkeys();
int pkey_set(int pkey, unsigned long rights, unsigned long flags)
{
    pkey_map = ((rights & 0x3) << (pkey-1));
    enforce_pkeys();
    return 0;
}

struct ttbr_param {
    uint64_t asid;
    uint64_t root_pt;
};

static struct ttbr_param ttbr_conf[] =
{
    /* 0 */{.asid = 0, .root_pt = (uint64_t)&root_page_table},
    /* 1 */{.asid = 1, .root_pt = (uint64_t)&root_page_table_1nA},
    /* 2 */{.asid = 2, .root_pt = (uint64_t)&root_page_table_1nwA},
    /* 3 */{.asid = 1, .root_pt = (uint64_t)&root_page_table_1nA},
};

#define ENH_SMART
#ifdef ENH_SMART
void enforce_pkeys()
{
    uint64_t asid = 0;
    uint64_t root_pt = 0;
    uint64_t ttbr = 0;

    struct ttbr_param ttbr_param = ttbr_conf[pkey_map];

    ttbr =  ttbr_param.root_pt | (ttbr_param.asid << 48UL);
    asm volatile( "msr TTBR0_EL1, %0\n" ::"r"(ttbr):);
    asm volatile("isb sy");
}
#else

uint64_t va_lvl_idx(uint64_t addr, uint64_t level)
{
    uint64_t idx;
    uint64_t msk;
    switch(level){
	case 0:
	    msk = (((1UL << 48)-1) >> 39) << 39;
	    return (addr & msk) >> 39;
	    break;
	case 1:
	    msk = (((1UL << 38)-1) >> 30) << 30;
	    return (addr & msk) >> 30;
	    break;
	case 2:
	    msk = (((1UL << 29)-1) >> 21) << 21;
	    return (addr & msk) >> 21;
	    break;
	case 3:
	    msk = (((1UL << 20)-1) >> 12) << 12;
	    return (addr & msk) >> 12;
	    break;
	default:
	    return -1;
    }
}

uint64_t * get_pte(uint64_t addr, uint64_t level, uint64_t next_table_addr)
{
    uint64_t idx = va_lvl_idx(addr, level); /* TODO */
    uint64_t *pte_addr = (uint64_t *)(next_table_addr + idx*8);
    uint64_t pte = *pte_addr;

    /* is valid */
    /* No need to check because we created page table before hand */
    /* if(!(pte & 1)) { */
    /* } */

    if((pte & 2) == 0){ /* block */
	uint64_t addr_mask = 0;
	switch(level){
	    case 1:
		addr_mask = (((1UL << 48)-1) >> 30) << 30;
		break;
	    case 2:
		addr_mask = (((1UL << 48)-1) >> 21) << 21;
		break;
	    default:
		return NULL;
	}
	uint64_t test_addr = (uint64_t)(pte & addr_mask);
	if (test_addr == addr){
	    return pte_addr;
	}
    } else if(level == 3){ /* page */
	uint64_t addr_mask = (((1UL << 48)-1) >> 12) << 12;
	uint64_t test_addr = (uint64_t)(pte & addr_mask);
	if (test_addr == addr){
	    return pte_addr;
	}
    } else { /* table */
	uint64_t next_table_addr;
	uint64_t addr_mask = (((1UL << 48)-1) >> 12) << 12;
	next_table_addr = pte & addr_mask;
	return get_pte(addr, level + 1, next_table_addr);
    }

    return pte_addr;
}

extern int state;
void enforce_pkeys()
{
    unsigned long long addr = 0x80000000;
    volatile uint64_t *ptep = get_pte(addr, 0, (uint64_t)&root_page_table);
    uint64_t pte = *ptep;
    uint64_t pkey = pkey_map & (3 << (1-1));
    switch(pkey){
	case 0: /* ALLOW */
	    pte = (PTE_SUPERPAGE | PTE_ENH_WA_FLAGS) + addr;
	    break;
	case 2: /* DISABLE WRITING */
	    pte = (PTE_SUPERPAGE | PTE_ENH_nWA_FLAGS) + addr;
	    break;
	case 1:
	case 3: /* DISABLE ACCESS */
	    pte = (PTE_ENH_nA_FLAGS) + addr;
	    break;
    }
    *ptep = pte;
    asm volatile("dsb nsh");
    /* switch(state){ */
	/* case 0: asm volatile("tlbi VAAE1, %0\n" :: "r"(addr)); break; */
    /* 	case 1: asm volatile("tlbi VAE1, %0\n" :: "r"(addr)); break; */
    /* 	case 2: asm volatile("tlbi VALE1, %0\n" :: "r"(addr)); break; */
    /* 	case 3: asm volatile("tlbi VMALLE1\n"); break; */
    /* } */
    asm volatile("tlbi VMALLE1\n");

    asm volatile("isb");
}
#endif

int pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot,
		unsigned long pkey)
{
   enforce_pkeys();
   return 0;
}

int pkey_alloc(void)
{
   return 1;
}

int pkey_free(unsigned long pkey)
{
   return 0;
}
