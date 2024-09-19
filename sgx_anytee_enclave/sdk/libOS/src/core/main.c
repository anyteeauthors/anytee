#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <plat.h>

enum {
    HC_E_SUCCESS = 0,
    HC_E_FAILURE = 1,
    HC_E_INVAL_ID = 2,
    HC_E_INVAL_ARGS = 3
};



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
};

#define HC_ENCLAVE 3

#define HC_ENCLAVE_ID      (HC_ENCLAVE << 16)
#define HC_ENCLAVE_CREATE  (HC_ENCLAVE_ID | SDSGX_CREATE)
#define HC_ENCLAVE_RESUME  (HC_ENCLAVE_ID | SDSGX_RESUME)
#define HC_ENCLAVE_OCALL   (HC_ENCLAVE_ID | SDSGX_OCALL)
#define HC_ENCLAVE_GOTO    (HC_ENCLAVE_ID | SDSGX_GOTO)
#define HC_ENCLAVE_EXIT    (HC_ENCLAVE_ID | SDSGX_EXIT)
#define HC_ENCLAVE_DELETE  (HC_ENCLAVE_ID | SDSGX_DELETE)

struct hvc_res{
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
};

#include <internal/thread_data.h>
thread_data_t thread_data;
#include <internal/arch.h>
ssa_gpr_t g_ssa_gpr;

static uint64_t bao_hvc(uint64_t fid, uint64_t x1, uint64_t x2,
                               uint64_t x3, struct hvc_res *res)
{
    register uint64_t r0 asm("x0") = fid;
    register uint64_t r1 asm("x1") = x1;
    register uint64_t r2 asm("x2") = x2;
    register uint64_t r3 asm("x3") = x3;

    asm volatile("hvc	#0\n"
                 : "=r"(r0), "=r"(r1), "=r"(r2), "=r"(r3)
                 : "r"(r0), "r"(r1), "r"(r2), "r"(r3));

    res->x0 = r0;
    res->x1 = r1;
    res->x2 = r2;
    res->x3 = r3;
    return r0;
}

void sdsgx_create(uint64_t config_addr)
{
    struct hvc_res res;
    bao_hvc(HC_ENCLAVE_CREATE, config_addr, 0, 0, &res);
}
void sdsgx_resume(uint64_t child_id)
{
    struct hvc_res res;
    bao_hvc(HC_ENCLAVE_RESUME, child_id, 0, 0, &res);
}
void sdsgx_goto(uint64_t child_id, uint64_t pc)
{
    struct hvc_res res;
    bao_hvc(HC_ENCLAVE_GOTO, child_id, pc, 0, &res);
}

uint64_t sdsgx_exit(struct hvc_res *res)
{
    bao_hvc(HC_ENCLAVE_EXIT, 0, 0, 0, res);
    return res->x1;
}

void sdsgx_delete()
{
    struct hvc_res res;
    bao_hvc(HC_ENCLAVE_DELETE, 0, 0, 0, &res);
}

struct g_ecall_table {
	size_t nr_ecall;
	struct {
	    void* ecall_addr;
	    uint8_t is_priv;
	    uint8_t is_switchless;
	} ecall_table[];
};
extern const struct g_ecall_table g_ecall_table;

extern uint8_t _sdsgx_shmem;
void* enclave_shmem = &_sdsgx_shmem;

struct sdsgx_ecall {
    int eid;
    int index;
    const void *ocall_table;
    void *ms;
};

#define SDSGX_ECALL_ENCLAVE  1
#define SDSGX_ADD_RGN 2

void handle_ecall(uint64_t cmd_id, struct hvc_res res)
{
    switch(cmd_id){
	case SDSGX_ECALL_ENCLAVE:
	    ssa_gpr_t *ssa_gpr = (ssa_gpr_t *)thread_data.first_ssa_gpr;
	    ssa_gpr->REG(sp_u) = res.x2;
	    thread_data.last_sp = res.x2; /* if we do ocallocs this is used to unwind */
	    struct sdsgx_ecall arg;
	    void (*fn)(uintptr_t);
	    memcpy(&arg, enclave_shmem, sizeof(struct sdsgx_ecall));
	    fn = g_ecall_table.ecall_table[arg.index].ecall_addr;
	    fn(arg.ms);
	    break;
	case SDSGX_ADD_RGN:
	    unsigned long paddr = res.x2;
	    unsigned long vaddr = res.x3;
	    break;
    }
}


void handle_ocall(uint64_t index, void *ms)
{
    struct sdsgx_ecall arg;
    struct hvc_res res;
    uint64_t cmd = 0;
    void (*fn)(uintptr_t);
    arg.index = index;
    arg.ms = ms;

    ssa_gpr_t *ssa_gpr = (ssa_gpr_t *)thread_data.first_ssa_gpr;
    uint64_t new_sp  = ssa_gpr->REG(sp_u);
    uint64_t old_sp = thread_data.last_sp;
    uint64_t calloc_size = old_sp - new_sp;

    memcpy(enclave_shmem, &arg, sizeof(struct sdsgx_ecall));

    bao_hvc(HC_ENCLAVE_OCALL, ssa_gpr->REG(sp_u), calloc_size, 0, &res);

    /* ssa_gpr->REG(sp_u) = res.x2; */
    /* thread_data.last_sp = res.x2; /1* if we do ocallocs this is used to unwind *1/ */
}
extern void handle_ocall(uint64_t index, void *ms);

extern uint64_t g_enclave_base;
extern uint64_t g_enclave_size;

extern int do_init_enclave(void *ms, void *tcs);

#include <internal/global_data.h>
extern struct global_data_t global_data;
extern uint8_t _heap_base;
uint64_t heap_base = &_heap_base;

void main(void)
{
    uint64_t idx = 0;
    uintptr_t args;
    uint64_t cmd = 0;
    struct hvc_res res;

    g_enclave_base = PLAT_MEM_BASE;
    g_enclave_size = PLAT_MEM_SIZE;


    g_global_data.sdk_version = SDK_VERSION_1_5;
    g_global_data.enclave_size = PLAT_MEM_SIZE;
    g_global_data.heap_offset = heap_base - PLAT_MEM_BASE;
    g_global_data.heap_size = 0x200000;
    g_global_data.rsrv_offset = 0;
    g_global_data.rsrv_size = 0;
    g_global_data.rsrv_executable = 0;
    g_global_data.thread_policy = 0;
    g_global_data.tcs_max_num = 0;
    g_global_data.tcs_num = 0;
    g_global_data.tcs_template[TCS_TEMPLATE_SIZE];
    g_global_data.layout_entry_num;
    g_global_data.reserved;
    g_global_data.enclave_image_address = PLAT_MEM_BASE;
    g_global_data.elrange_start_address = PLAT_MEM_BASE;
    g_global_data.elrange_size = PLAT_MEM_SIZE;
    do_init_enclave(NULL, NULL);
    thread_data.first_ssa_gpr = (sys_word_t)&g_ssa_gpr;

    /* printf("(ENCLAVE) Running!\n"); */
    cmd = sdsgx_exit(&res);

    while (1) {
	handle_ecall(cmd, res);

	cmd = sdsgx_exit(&res);
    }
}
