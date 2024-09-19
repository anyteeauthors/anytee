#include "Enclave_t.h"
#include "Ocall_wrappers.h"

#include <openssl/ssl.h>

#define	INADDR_NONE		((unsigned long int) 0xffffffff)

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

/* int */
/* isascii(int c) */
/* { */
/* 	return((c & ~0x7F) == 0); */
/* } */

/* inet_aton from https://android.googlesource.com/platform/bionic.git/+/android-4.0.1_r1/libc/inet/inet_aton.c */
static int inet_aton(const char *cp, struct in_addr *addr)
{
	u_long val, base, n;
	char c;
	u_long parts[4], *pp = parts;

	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
		val = 0; base = 10;
		if (*cp == '0') {
			if (*++cp == 'x' || *cp == 'X')
				base = 16, cp++;
			else
				base = 8;
		}
		while ((c = *cp) != '\0') {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				cp++;
				continue;
			}
			if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) +
					(c + 10 - (islower(c) ? 'a' : 'A'));
				cp++;
				continue;
			}
			break;
		}
		if (*cp == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16-bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3 || val > 0xff)
				return (0);
			*pp++ = val, cp++;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && (!isascii(*cp) || !isspace(*cp)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

		case 1:				/* a -- 32 bits */
			break;

		case 2:				/* a.b -- 8.24 bits */
			if (val > 0xffffff)
				return (0);
			val |= parts[0] << 24;
			break;

		case 3:				/* a.b.c -- 8.8.16 bits */
			if (val > 0xffff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16);
			break;

		case 4:				/* a.b.c.d -- 8.8.8.8 bits */
			if (val > 0xff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
			break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}

static in_addr_t inet_addr(const char *cp)
{
	struct in_addr val;

	if (inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}

static int create_socket_client(const char *ip, uint32_t port)
{
	int sockfd;
	struct sockaddr_in dest_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0) {
		printe("socket");
		return 0;
	}

	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(port);
	dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
	memset(&(dest_addr.sin_zero), '\0', 8);

	/* printl("Connecting..."); */
	if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
		printe("Cannot connect");
		return 0;
	}

	return sockfd;
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
#define STR(s)  #s
#define XSTR(s)  STR(s)

#define MRS(reg) ({\
    unsigned long _temp;\
    asm volatile("mrs %0, " XSTR(reg) "\n\r" : "=r"(_temp));\
    _temp;\
})

#define MSR(reg, var) asm volatile("msr " XSTR(reg)  ", %0\n\r" ::"r"(var))
#define  ARMV8_PMEVTYPER_EVTCOUNT_MASK (0xFFFF)
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
    /* unsigned long evtCount; */

    /* evtCount = 0x0017; /1* L2D CACHE REFILL *1/ */
    /* evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK; */
    /* MSR(pmevtyper0_el0, evtCount); */

    /* evtCount = 0x0003; /1* L1 DCACHE *1/ */
    /* evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK; */
    /* MSR(pmevtyper1_el0, evtCount); */

    /* evtCount = 0x0001; /1* L1 ICACHE *1/ */
    /* evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK; */
    /* MSR(pmevtyper2_el0, evtCount); */

    /* evtCount = 0x0005; /1* TLBD *1/ */
    /* evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK; */
    /* MSR(pmevtyper3_el0, evtCount); */

    /* evtCount = 0x0002; /1* TLBI *1/ */
    /* evtCount &= ARMV8_PMEVTYPER_EVTCOUNT_MASK; */
    /* MSR(pmevtyper4_el0, evtCount); */

    /* MSR(pmcntenset_el0, MRS(pmcntenset_el0) | ((1 << 31)-1) | (1 << 31)); */
    /* MSR(PMCR_EL0, MRS(PMCR_EL0) | ((1L)) | (1L << 1)); */
    /* asm volatile ("isb sy"); */
}

static inline void read_pmu()
{
    /* MSR(PMCR_EL0, MRS(PMCR_EL0) & (~(1L))); */
    /* asm volatile ("isb sy"); */
    /* unsigned long val = 0; */

    /* l2   = MRS(PMEVCNTR0_EL0); */
    /* l1d  = MRS(PMEVCNTR1_EL0); */
    /* l1i  = MRS(PMEVCNTR2_EL0); */
    /* tlbd = MRS(PMEVCNTR3_EL0); */
    /* tlbi = MRS(PMEVCNTR4_EL0); */
}

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

#define USE_ENH
#include <enh.h>

int state = 0;
#ifdef USE_ENH
voidenh_test()
{
    int pkey = pkey_alloc();
    int status;
    if (pkey == -1){
	printe("pkey_alloc");
	return;
    }

    size_t i = 1000000;
    prepare_pmu();
    volatile unsigned long long start = 0;
    volatile unsigned long long *ptr = (unsigned long long *)0x80000000;
    volatile unsigned long long tmp = 0;
    asm volatile ("mrs %0, CNTVCT_EL0\n":"=r"(start));
    while(i--){
	status = pkey_set(pkey, 0x0, 0);
	if (status){
	    printe("pkey_set enable access");
	    return;
	}
	(*ptr)++;
	tmp = (*ptr);
	status = pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
	if (status){
	    printe("pkey_set stop acess");
	    return;
	}
    }
    volatile unsigned long long end = 0;
    asm volatile ("mrs %0, CNTVCT_EL0\n":"=r"(end));
    unsigned long long elapsed = end - start;
    read_pmu();
    printl("\nelapsed\t   l1d\t  l1i\t  l2\t tlbd\t  tlbi\t\n"
	    "%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t\n",
	    elapsed, l1d, l1i, l2, tlbd, tlbi);
}
#endif

unsigned char read_buf[16384];
extern unsigned int OPENSSL_armcap_P;
void ecall_start_tls_client(void)
{
    SSL *ssl;
    int sock;
    SSL_CTX *ctx;
    OPENSSL_armcap_P = 0x3f;
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    const char *serv_ip = "127.0.0.1";
    uint32_t serv_port = 4433;
    init_openssl();

    printl("OPENSSL a Version = %s", SSLeay_version(SSLEAY_VERSION));
#ifdef USE_ENH
    printl("Using ENH");
    unsigned long long int v0 = MRS(PMCEID0_EL0);
    unsigned long long int v1 = MRS(PMCEID1_EL0);
    printl("ID0 0x%llx\tID1 0x%llx\n", v0, v1);

#endif
/* #ifdef USE_ENH */
/*    enh_test(); */
/*     return; */
/* #endif */
    volatile unsigned long long *ptr = (unsigned long long *)0x80000000;
    volatile unsigned long long tmp = 0;
    int counter = 0;
    while (1) {
        hvc_res res;
        bao_hvc(3 << 16 | 8, 0 , 0, 0, &res);
	prepare_pmu();
	volatile unsigned long long start = 0;
	asm volatile ("mrs %0, CNTVCT_EL0\n":"=r"(start));
	ctx = create_context();
	SSL_CTX_set_options(ctx, flags);
	sock = create_socket_client(serv_ip, serv_port);
	/* printl("Connects to TLS server success"); */

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);
	if (SSL_connect(ssl) <= 0) {
	    printe("SSL_connect");
	    break;
	}

#ifdef USE_ENH
	int pkey = pkey_alloc();
	int status;
	if (pkey == -1){
	    printe("pkey_alloc");
	    return;
	}

	status = pkey_mprotect(ssl->session, getpagesize(),
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
	/* printl("ciphersuite: %s", SSL_get_current_cipher(ssl)->name); */
	/* Send buffer to TLS server */
#ifdef USE_ENH
	status = pkey_set(pkey, 0x0, 0);
	if (status){
	    printe("pkey_set enable access");
	    return;
	}
#endif
	const char *send_buf = "Hello TLS Server!";
	/* SSL_write(ssl, send_buf, strlen(send_buf)+1); */
#ifdef USE_ENH
	status = pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
	if (status){
	    printe("pkey_set stop acess");
	    return;
	}
#endif
	int r, acc;
	acc = 0;
	do{
#ifdef USE_ENH
	status = pkey_set(pkey, 0x0, 0);
	if (status){
	    printe("pkey_set enable access");
	    return;
	}
#endif
	    r = SSL_read(ssl, read_buf, sizeof(read_buf));
	    /* printl("r: %d\n", r); */
	    acc += r;
	    /* force a translation in a protected address */
	    (*ptr)++;
	    tmp = (*ptr);
	    SSL_write(ssl, send_buf, strlen(send_buf)+1);
#ifdef USE_ENH
	status = pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
	if (status){
	    printe("pkey_set stop acess");
	    return;
	}
#endif
	}while(r);

#ifdef USE_ENH
	status = pkey_set(pkey, 0x0, 0);
	if (status){
	    printe("pkey_set enable access");
	    return;
	}
#endif
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	sgx_close(sock);

	volatile unsigned long long end = 0;
	asm volatile ("mrs %0, CNTVCT_EL0\n":"=r"(end));
	unsigned long long elapsed = end - start;
	read_pmu();
	printl("%d\nelapsed\t   l1d\t  l1i\t  l2\t tlbd\t  tlbi\t size\n"
		"%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\n",
		++counter, elapsed, l1d, l1i, l2, tlbd, tlbi, acc);

        printl("\nenclv_aborts\t   n_resumes\t  irqs\t  n_calls\t o_calls\t\n"
		"%llu\t%llu\t%llu\t%llu\t%llu\n",
		res.x1, res.x2, res.x3, res.x4, res.x5);
    }
    cleanup_openssl();
}
