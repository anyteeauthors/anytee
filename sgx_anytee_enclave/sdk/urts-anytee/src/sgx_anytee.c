#include <sys/ioctl.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <sdsgx.h>
#include <sgx_error.h>

static int driverfd;
static void *userspace;
static size_t full_size;
static size_t shmem_size;
static uintptr_t phys_addr;

enum {
    SDSGX_CREATE  = 0,
    SDSGX_ECALL   = 1,
    SDSGX_OCALL   = 2,
    SDSGX_RESUME  = 3,
    SDSGX_GOTO    = 4,
    SDSGX_EXIT    = 5,
    SDSGX_DELETE  = 6,
    SDSGX_ADD_RGN = 7,
    SDSGX_INFO    = 8,
    SDSGX_FAULT   = 9,
};


struct sdsgx_ioctl_create {
    int eid;
    unsigned long phys_addr;
};

struct sdsgx_ioctl_ecall {
    struct {
	int eid;
	int index;
	const void *ocall_table;
	void *ms;
	unsigned long sp;
    } in;

    struct {
	int ret;
	size_t calloc_size;
	size_t fault_addr;
    } out;
};

struct sdsgx_ioctl_destroy {
    int eid;
};

struct sdsgx_ioctl_add_rgn {
    int eid;
    unsigned long virt_addr;
};

int sgx_oc_cpuidex(int * cpuinfo, int leaf, int subleaf)
{
    return 0;
}

struct ocall_table_Enclave {
	size_t nr_ocall;
	void *table[];
};

#define OCALL 100
#include <alloca.h>

int sgx_ecall(int eid, int index, const void* ocall_table, void* ms)
{
    struct ocall_table_Enclave *ocall_tbl;
    unsigned long sp;
    sgx_status_t (*ocall_fn)(void *);
    struct sdsgx_ioctl_ecall arg = {.in ={.eid = eid, .index = index, .ms = ms}};


    fflush(NULL);
    ocall_tbl = (struct ocall_table_Enclave*) ocall_table;

    int done = 0;
    int res = 0;
    asm volatile ("mov %0, sp\n":"=r"(sp));
    arg.in.sp = sp;
    ioctl(driverfd, SDSGX_DEVICE_IOC_CALL_ENCLAVE, &arg);
    do{
	switch(arg.out.ret){
	    case 0:
		done = 1;
		break;
	    case 1: /* EXCEPTION */
		break;
	    case SDSGX_FAULT:
		volatile unsigned int *a = arg.out.fault_addr;
		*a = *a;
		struct sdsgx_ioctl_add_rgn t_arg;
		t_arg.eid = eid;
		t_arg.virt_addr = a;
		ioctl(driverfd, SDSGX_DEVICE_IOC_ADD_RGN, &t_arg);
		break;
	    case SDSGX_OCALL: /* OCALL */{
		void *ptr = alloca(arg.out.calloc_size);
		if(ptr != arg.in.ms)
		    printf("Error allocating stack object.");
		ocall_fn = ocall_tbl->table[arg.in.index];
		ocall_fn(arg.in.ms);
		asm volatile ("add sp, sp, %0\n"::"r"(arg.out.calloc_size));
	       }
	    break;
	}
	if(!done){
	    asm volatile ("mov %0, sp\n":"=r"(sp));
	    arg.in.sp = sp;
	    ioctl(driverfd, SDSGX_DEVICE_IOC_RESUME_ENCLAVE, &arg);
	}
     }while(!done);
    return 0;
}

int sgx_create_enclave(char* filename, int debug, void* sgx_create_enclave, int* launch_token_updated, int* global_eid, void* misc_attr)
{
    int ret = 0;
    sdsgx_place_config(filename, &phys_addr, &userspace, &full_size, &shmem_size);

    ret = open(SDSGX_DEVICE, O_RDWR);
    if (ret < 0)
    {
	perror("Could not open " SDSGX_DEVICE);
	exit(EXIT_FAILURE);
    }
    driverfd = ret;
    struct sdsgx_ioctl_create arg;
    arg.phys_addr = phys_addr;
    ioctl(driverfd, SDSGX_DEVICE_IOC_CREATE_CMA, &arg);
    *global_eid = arg.eid;

    return 0;
}

int sgx_destroy_enclave(int global_eid)
{
    struct sdsgx_ioctl_destroy arg;
    arg.eid = global_eid;
    ioctl(driverfd, SDSGX_DEVICE_IOC_DESTROY_ENCLAVE, &arg);
    sdsgx_free_space(full_size, phys_addr, userspace);
}

/* wait on untrusted event */
int sgx_thread_wait_untrusted_event_ocall(const void *self)
{
    return SGX_SUCCESS;
}

/* set untrusted event */
int sgx_thread_set_untrusted_event_ocall(const void *waiter)
{
    return SGX_SUCCESS;
}

int sgx_thread_set_multiple_untrusted_events_ocall(const void **waiters, size_t total)
{
    return SGX_SUCCESS;
}

int sgx_thread_setwait_untrusted_events_ocall(const void *waiter, const void *self)
{
    return SGX_SUCCESS;
}
int sgx_bao_info(int* global_eid, struct sdsgx_info* info)
{
    ioctl(driverfd, SDSGX_DEVICE_IOC_PRINT_INFO, info);
}
