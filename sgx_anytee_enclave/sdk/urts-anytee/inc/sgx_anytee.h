struct sdsgx_info{
    unsigned long calls;
    unsigned long resumes;
};

void sgx_oc_cpuidex(int * cpuinfo, int leaf, int subleaf);
void sgx_thread_wait_untrusted_event_ocall();
void sgx_thread_set_untrusted_event_ocall();
void sgx_thread_setwait_untrusted_events_ocall();
void sgx_thread_set_multiple_untrusted_events_ocall();
void sgx_ecall(int eid, int, const void* ocall_table, void* ms );
void sgx_create_enclave(char * filename, int debug, void* sgx_create_enclave, int* launch_token_updated, int* global_eid, void* misc_attr);
void sgx_destroy_enclave(int* global_eid);
int sgx_bao_info(int* global_eid, struct sdsgx_info *info);
