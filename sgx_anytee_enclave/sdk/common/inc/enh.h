#ifndef _ENH_H_
#define _ENH_H_

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif


#define MAP_FAILED	((void *) -1)


#define MREMAP_MAYMOVE		1
#define MREMAP_FIXED		2
#define MREMAP_DONTUNMAP	4

#define OVERCOMMIT_GUESS		0
#define OVERCOMMIT_ALWAYS		1
#define OVERCOMMIT_NEVER		2

#define MAP_SHARED	0x01		/* Share changes */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_SHARED_VALIDATE 0x03	/* share + validate extension flags */

/*
 * Huge page size encoding when MAP_HUGETLB is specified, and a huge page
 * size other than the default is desired.  See hugetlb_encode.h.
 * All known huge page size encodings are provided here.  It is the
 * responsibility of the application to know which sizes are supported on
 * the running system.  See mmap(2) man page for details.
 */
#define MAP_HUGE_SHIFT	HUGETLB_FLAG_ENCODE_SHIFT
#define MAP_HUGE_MASK	HUGETLB_FLAG_ENCODE_MASK

#define MAP_HUGE_16KB	HUGETLB_FLAG_ENCODE_16KB
#define MAP_HUGE_64KB	HUGETLB_FLAG_ENCODE_64KB
#define MAP_HUGE_512KB	HUGETLB_FLAG_ENCODE_512KB
#define MAP_HUGE_1MB	HUGETLB_FLAG_ENCODE_1MB
#define MAP_HUGE_2MB	HUGETLB_FLAG_ENCODE_2MB
#define MAP_HUGE_8MB	HUGETLB_FLAG_ENCODE_8MB
#define MAP_HUGE_16MB	HUGETLB_FLAG_ENCODE_16MB
#define MAP_HUGE_32MB	HUGETLB_FLAG_ENCODE_32MB
#define MAP_HUGE_256MB	HUGETLB_FLAG_ENCODE_256MB
#define MAP_HUGE_512MB	HUGETLB_FLAG_ENCODE_512MB
#define MAP_HUGE_1GB	HUGETLB_FLAG_ENCODE_1GB
#define MAP_HUGE_2GB	HUGETLB_FLAG_ENCODE_2GB
#define MAP_HUGE_16GB	HUGETLB_FLAG_ENCODE_16GB

    #define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */
#define PROT_SEM	0x8		/* page may be used for atomic ops */
/*			0x10		   reserved for arch-specific use */
/*			0x20		   reserved for arch-specific use */
#define PROT_NONE	0x0		/* page can not be accessed */
#define PROT_GROWSDOWN	0x01000000	/* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP	0x02000000	/* mprotect flag: extend change to end of growsup vma */

/* 0x01 - 0x03 are defined in linux/mman.h */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */

/* 0x0100 - 0x4000 flags are defined in asm-generic/mman.h */
#define MAP_POPULATE		0x008000	/* populate (prefault) pagetables */
#define MAP_NONBLOCK		0x010000	/* do not block on IO */
#define MAP_STACK		0x020000	/* give out an address that is best suited for process/thread stacks */
#define MAP_HUGETLB		0x040000	/* create a huge page mapping */
#define MAP_SYNC		0x080000 /* perform synchronous page faults for the mapping */
#define MAP_FIXED_NOREPLACE	0x100000	/* MAP_FIXED which doesn't unmap underlying mapping */

#define MAP_UNINITIALIZED 0x4000000	/* For anonymous mmap, memory could be
					 * uninitialized */

/*
 * Flags for mlock
 */
#define MLOCK_ONFAULT	0x01		/* Lock pages in range after they are faulted in, do not prefault */

#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */

#define MADV_NORMAL	0		/* no further special treatment */
#define MADV_RANDOM	1		/* expect random page references */
#define MADV_SEQUENTIAL	2		/* expect sequential page references */
#define MADV_WILLNEED	3		/* will need these pages */
#define MADV_DONTNEED	4		/* don't need these pages */

/* common parameters: try to keep these consistent across architectures */
#define MADV_FREE	8		/* free pages only if memory pressure */
#define MADV_REMOVE	9		/* remove these pages & resources */
#define MADV_DONTFORK	10		/* don't inherit across fork */
#define MADV_DOFORK	11		/* do inherit across fork */
#define MADV_HWPOISON	100		/* poison a page for testing */
#define MADV_SOFT_OFFLINE 101		/* soft offline page for testing */

#define MADV_MERGEABLE   12		/* KSM may merge identical pages */
#define MADV_UNMERGEABLE 13		/* KSM may not merge identical pages */

#define MADV_HUGEPAGE	14		/* Worth backing with hugepages */
#define MADV_NOHUGEPAGE	15		/* Not worth backing with hugepages */

#define MADV_DONTDUMP   16		/* Explicity exclude from the core dump,
					   overrides the coredump filter bits */
#define MADV_DODUMP	17		/* Clear the MADV_DONTDUMP flag */

#define MADV_WIPEONFORK 18		/* Zero memory on fork, child only */
#define MADV_KEEPONFORK 19		/* Undo MADV_WIPEONFORK */

#define MADV_COLD	20		/* deactivate these pages */
#define MADV_PAGEOUT	21		/* reclaim these pages */

/* compatibility flags */
#define MAP_FILE	0

#define PKEY_DISABLE_ACCESS	0x1
#define PKEY_DISABLE_WRITE	0x2
#define KEY_ACCESS_MASK	(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)

#define errExit(x) return;
#define exit(x) return;
#define pror(x) return;

void *mmap(void *addr, size_t length, int prot, int flags, int fd, size_t offset);
int munmap(void *addr, size_t length);
size_t getpagesize();

int pkey_set(int pkey, unsigned long rights, unsigned long flags);

int pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot,
	unsigned long pkey);
int pkey_alloc(void);
int pkey_free(unsigned long pkey);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENH_H_ */

