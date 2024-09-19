#include "Enclave_t.h"
#include "Ocall_wrappers.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>


#include <mpk.h>

static void init_openssl()
{
	OpenSSL_add_ssl_algorithms();
	OpenSSL_add_all_ciphers();
	SSL_load_error_strings();
}

static void cleanup_openssl()
{
    EVP_cleanup();
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printe("Unable to create SSL context");
        return NULL;
    }
    return ctx;
}

static int password_cb(char *buf, int size, int rwflag, void *password)
{
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

static EVP_PKEY *generatePrivateKey()
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    return pkey;
}

static X509 *generateCertificate(EVP_PKEY *pkey)
{
    X509 *x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), (long)60*60*24*365);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"YourCN", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_md5());
    return x509;
}

static void configure_context(SSL_CTX *ctx)
{
	EVP_PKEY *pkey = generatePrivateKey();
	X509 *x509 = generateCertificate(pkey);

	SSL_CTX_use_certificate(ctx, x509);
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	SSL_CTX_use_PrivateKey(ctx, pkey);

	RSA *rsa=RSA_generate_key(512, RSA_F4, NULL, NULL);
	SSL_CTX_set_tmp_rsa(ctx, rsa);
	RSA_free(rsa);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
}

static int create_socket_server(int port)
{
    int s, optval = 1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printe("sgx_socket");
        return -1;
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
        printe("sgx_setsockopt");
        return -1;
    }
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printe("sgx_bind");
        return -1;
    }
    if (listen(s, 128) < 0) {
        printe("sgx_listen");
        return -1;
    }
    return s;
}

#define STR(s)  #s
#define XSTR(s)  STR(s)

#define MRS(reg) ({\
    unsigned long _temp;\
    asm volatile("mrs %0, " XSTR(reg) "\n\r" : "=r"(_temp));\
    _temp;\
})

#define MSR(reg, var) asm volatile("msr " XSTR(reg)  ", %0\n\r" ::"r"(var))
#define  ARMV8_PMEVTYPER_EVTCOUNT_MASK (0xFFFF)
struct hvc_res{
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
    uint64_t x5;
};

static uint64_t bao_hvc(uint64_t fid, uint64_t x1, uint64_t x2,
                               uint64_t x3, struct hvc_res *res)
{
    register uint64_t r0 asm("x0") = fid;
    register uint64_t r1 asm("x1") = x1;
    register uint64_t r2 asm("x2") = x2;
    register uint64_t r3 asm("x3") = x3;
    register uint64_t r4 asm("x4");
    register uint64_t r5 asm("x5");

    asm volatile("hvc	#0\n"
                 : "=r"(r0), "=r"(r1), "=r"(r2), "=r"(r3), "=r"(r4), "=r"(r5)
                 : "r"(r0), "r"(r1), "r"(r2), "r"(r3));

    res->x0 = r0;
    res->x1 = r1;
    res->x2 = r2;
    res->x3 = r3;
    res->x4 = r4;
    res->x5 = r5;
    return r0;
}

unsigned long long elapsed;
unsigned long long exec;
unsigned long long cpu_cy;
unsigned long long l1d;
unsigned long long l1i;
unsigned long long l2;
unsigned long long tlbd;
unsigned long long tlbi;
static inline void prepare_pmu()
{
    unsigned long evtCount;

    evtCount = 0x0017; /* L2D CACHE REFILL */
    evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK;
    MSR(pmevtyper0_el0, evtCount);

    evtCount = 0x0004; /* L1 DCACHE CYCLES */
    evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK;
    MSR(pmevtyper1_el0, evtCount);

    evtCount = 0x0014; /* L1 ICACHE CYCLES */
    evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK;
    MSR(pmevtyper2_el0, evtCount);

    evtCount = 0x0025; /* TLBD */
    evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK;
    MSR(pmevtyper3_el0, evtCount);

    evtCount = 0x0026; /* TLBI */
    evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK;
    MSR(pmevtyper4_el0, evtCount);

    MSR(pmcntenset_el0, MRS(pmcntenset_el0) | ((1 << 31)-1) | (1 << 31));
    MSR(PMCR_EL0, MRS(PMCR_EL0) | ((1L)) | (1L << 1));
    asm volatile ("isb sy");
}

static inline void read_pmu()
{
    /* MSR(PMCR_EL0, MRS(PMCR_EL0) & (~(1L))); */
    asm volatile ("isb sy");
    unsigned long val = 0;

    l2   = MRS(PMEVCNTR0_EL0);
    exec = MRS(PMEVCNTR1_EL0);
    l1d  = MRS(PMEVCNTR2_EL0);
    l1i  = MRS(PMEVCNTR3_EL0);
    tlbd = MRS(PMEVCNTR4_EL0);
    tlbi = MRS(PMEVCNTR5_EL0);
}

#define USE_ENH

unsigned char read_buf[16384];
extern unsigned int OPENSSL_armcap_P;
void ecall_start_tls_server(void)
{
    int sock;
    SSL_CTX *ctx;
    OPENSSL_armcap_P = 0x3f;

    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

/* #define USE_ENH */
#ifdef USE_ENH
    printl("UsingENH");
#endif

    sock = create_socket_server(4433);
    if(sock < 0) {
        printe("create_socket_client");
	return;
    }

    /* Handle SSL/TLS connections */
    while(1) {
        struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *cli;
        int r = 0;

        /* printl("Wait for new connection..."); */
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            printe("Unable to accept");
	    return;
        }

	cli = SSL_new(ctx);

        SSL_set_fd(cli, client);

	if (SSL_accept(cli) <= 0) {
            printe("SSL_accept");
	    return;
        }

#ifdef USE_ENH
	int pkey = pkey_alloc();
	int status;
	if (pkey == -1){
	    printe("pkey_alloc");
	    return;
	}

	status = pkey_mprotect(cli->session, getpagesize(),
		PROT_READ | PROT_WRITE, pkey);
	if (status == -1){
	    printe("pkey_mprotect");
	    return;
	}

	status = pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
	if (status){
	    printe("pkey_set stop acess");
	    return;
	}
#endif

        /* printl("ciphersuit: %s", SSL_get_current_cipher(cli)->name); */
        /* Receive buffer from TLS server */


	/* hvc_res res; */
	/* bao_hvc(3 << 16 | 8, 0 , 0, 0, &res); */
	volatile unsigned long long start = 0;
	prepare_pmu();
	asm volatile ("mrs %0, CNTVCT_EL0\n":"=r"(start));
#ifdef USE_ENH
	status = pkey_set(pkey, 0x0, 0);
	if (status){
	    printe("pkey_set enable access");
	    return;
	}
#endif
        r = SSL_read(cli, read_buf, sizeof(read_buf));

#ifdef USE_ENH
	status = pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
	if (status){
	    printe("pkey_set stop acess");
	    return;
	}
#endif
	volatile unsigned long long end = 0;
	asm volatile ("mrs %0, CNTVCT_EL0\n":"=r"(end));
	unsigned long long elapsed = end - start;
	read_pmu();

	/* bao_hvc(3 << 16 | 8, 0 , 0, 0, &res); */
	/* printl("\nelapsed\tl2\texec\tsize\n" */
	/* 	"%llu\t%llu\t%llu\t%d\n" */
	/* 	"\naborts\tresumes\tirqs\tecalls\tocalls\n" */
	/* 	"%lu\t%lu\t%lu\t%lu\t%lu\n", */
	/* 	elapsed, l2, exec, r, */
	/* 	res.x1, res.x2, res.x3, res.x4, res.x5); */
	printl("\nelapsed\tcpu_cy\tl2\texec\tsize\n"
		"%llu\t%llu\t%llu\t%llu\t%d\n",
		elapsed, cpu_cy, l2, exec, r);
        memset(read_buf, 0, sizeof(read_buf));


#ifdef USE_ENH
	status = pkey_set(pkey, 0x0, 0);
	if (status){
	    printe("pkey_set enable access");
	    return;
	}
#endif

        /* printl("Close SSL/TLS client"); */
        SSL_free(cli);
        sgx_close(client);
    }

    sgx_close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
