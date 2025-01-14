/*
 * sdsgx device core
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <asm/io.h>
#include <asm/memory.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/mm.h>

#include "sdsgx.h"
#include <linux/string.h>

/* Device major umber */
static dev_t sdsgx_device_dev_t;
struct class *cl;

struct sdsgx_device sdsgx_array[MAX_DEVICES];

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



struct sdsgx_ioctl_add_rgn {
    int eid;
    unsigned long virt_addr;
};

enum {
    sdsgx_CREATE  = 0,
    sdsgx_ECALL   = 1,
    sdsgx_OCALL   = 2,
    sdsgx_RESUME  = 3,
    sdsgx_GOTO    = 4,
    sdsgx_EXIT    = 5,
    sdsgx_DELETE  = 6,
    sdsgx_ADD_RGN = 7,
    sdsgx_INFO    = 8,
    sdsgx_FAULT   = 9,
};


#define HC_ENCLAVE 3

#define HC_ENCLAVE_ID      (HC_ENCLAVE << 16)
#define HC_ENCLAVE_CREATE  (HC_ENCLAVE_ID | sdsgx_CREATE)
#define HC_ENCLAVE_RESUME  (HC_ENCLAVE_ID | sdsgx_RESUME)
#define HC_ENCLAVE_ECALL   (HC_ENCLAVE_ID | sdsgx_ECALL)
#define HC_ENCLAVE_GOTO    (HC_ENCLAVE_ID | sdsgx_GOTO)
#define HC_ENCLAVE_EXIT    (HC_ENCLAVE_ID | sdsgx_EXIT)
#define HC_ENCLAVE_DELETE  (HC_ENCLAVE_ID | sdsgx_DELETE)
#define HC_ENCLAVE_ADD_RGN  (HC_ENCLAVE_ID | sdsgx_ADD_RGN)
#define HC_ENCLAVE_INFO  (HC_ENCLAVE_ID | sdsgx_INFO)

#define sdsgx_RET_OK  0
#define sdsgx_RET_EXCEPTION  0

/* irq */
static irqreturn_t sdsgx_irq_handler(int irq, void *device_id)
{
	struct sdsgx_device *member_sdsgx_device = NULL;
	pr_info("interrupt occurred on IRQ %d\n", irq);

	member_sdsgx_device = device_id;

	member_sdsgx_device->data_available = 1;

	/* Wake up any possible sleeping process */
	wake_up_interruptible(&member_sdsgx_device->queue);

	return IRQ_NONE;
}

struct hvc_res{
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
};

static uint64_t sdsgx_hvc(uint64_t fid, uint64_t x1, uint64_t x2,
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

/* Reade/Write Validation */

static bool is_rw_valid(struct sdsgx_device *member_sdsgx_device,
			size_t count, loff_t *ppos)
{
	loff_t last_pos;

	if (*ppos > member_sdsgx_device->shared_memory.size) {
		return false;
	}

	last_pos = (*ppos + count);

	return last_pos <= member_sdsgx_device->shared_memory.size;
}

static bool is_write_valid(struct sdsgx_device *member_sdsgx_device,
			   size_t count, loff_t *ppos)
{
	return is_rw_valid(member_sdsgx_device, count, ppos);
}

static bool is_read_valid(struct sdsgx_device *member_sdsgx_device,
			  size_t count, loff_t *ppos)
{
	return is_rw_valid(member_sdsgx_device, count, ppos);
}

/* Read and Write Methods */

static ssize_t sdsgx_device_read(struct file *filp, char *buf,
				      size_t count, loff_t *ppos)
{
	struct sdsgx_device *member_sdsgx_device = filp->private_data;
	int ret;

	/* Wait for the wake up event... */
	//ret = wait_event_interruptible(
	//	member_sdsgx_device->queue,
	//	member_sdsgx_device->data_available);
	//if (ret != 0)
	//	goto exit;

	pr_info("Data is available now!\n");

	if (!is_read_valid(member_sdsgx_device, count, ppos)) {
		pr_info("invalid reading [%lu], ppos %llx\n", count, *ppos);
		return -1;
	}

	pr_info("reading [%lu], from %p\n", count,
		member_sdsgx_device->shared_memory.ptr + *ppos);

	if (!copy_to_user(buf,
			  &member_sdsgx_device->shared_memory.ptr[*ppos],
			  count)) {
		return 0;
	}

	return count;

exit:
	return 0;
}

static ssize_t sdsgx_device_write(struct file *filp, const char *buf,
				       size_t count, loff_t *ppos)
{
	struct sdsgx_device *member_sdsgx_device = filp->private_data;
	if (!is_write_valid(member_sdsgx_device, count, ppos)) {
		pr_info("invalid writing [%lu], ppos %llx\n", count, *ppos);
		return -1;
	}

	pr_info("writing [%lu], from %llx\n", count,
		(long long unsigned int)(member_sdsgx_device->shared_memory
						 .ptr +
					 *ppos));

	if (!copy_from_user(&member_sdsgx_device->shared_memory.ptr[*ppos],
			    buf, count)) {
		return -2;
	}

	pr_info("%s", &member_sdsgx_device->shared_memory.ptr[*ppos]);

	(*ppos) += count;

	return count;
}

static int
_sdsgx_device_open(struct sdsgx_device *member_sdsgx_device)
{
	kobject_get(&member_sdsgx_device->dev->kobj);

	return 0;
}

static int sdsgx_device_open(struct inode *inode, struct file *filp)
{
	struct sdsgx_device *member_sdsgx_device =
		container_of(inode->i_cdev, struct sdsgx_device, cdev);
	filp->private_data = member_sdsgx_device;

	return _sdsgx_device_open(member_sdsgx_device);
}

static int
_sdsgx_device_release(struct sdsgx_device *member_sdsgx_device)
{
	kobject_put(&member_sdsgx_device->dev->kobj);

	return 0;
}

static int sdsgx_device_release(struct inode *inode, struct file *filp)
{
	struct sdsgx_device *member_sdsgx_device =
		container_of(inode->i_cdev, struct sdsgx_device, cdev);
	filp->private_data = NULL;

	return _sdsgx_device_release(member_sdsgx_device);
}

static unsigned long virt_to_phys_user(void *addr)
{
    // struct mm_struct *mm : The memory descriptor of the current process.
    // unsigned long address: The virtual address to be translated.
    struct mm_struct *mm;
    pgd_t *pgdp;
    pgd_t pgd;
    struct page *pg;
    unsigned long phys;

    mm = current->active_mm;
    pgdp = pgd_offset(mm, addr);
    pgd = READ_ONCE(*pgdp);

    /* assumes for levels of page tables */
    do {
	    p4d_t *p4dp, p4d;
	    pud_t *pudp, pud;
	    pmd_t *pmdp, pmd;
	    pte_t *ptep, pte;

	    if (pgd_none(pgd) || pgd_bad(pgd))
		    break;

	    p4dp = p4d_offset(pgdp, addr);
	    p4d = READ_ONCE(*p4dp);
	    if (p4d_none(p4d) || p4d_bad(p4d))
		    break;

	    pudp = pud_offset(p4dp, addr);
	    pud = READ_ONCE(*pudp);
	    if (pud_none(pud) || pud_bad(pud))
		    break;

	    pmdp = pmd_offset(pudp, addr);
	    pmd = READ_ONCE(*pmdp);
	    if (pmd_none(pmd) || pmd_bad(pmd))
		    break;

	    ptep = pte_offset_map(pmdp, addr);
	    pte = READ_ONCE(*ptep);
	    pg = pte_page(pte);
	    phys = page_to_phys(pg);
	    pte_unmap(ptep);
    } while(0);

    return phys;
}

static int
sdsgx_create(struct sdsgx_device *member_sdsgx_device,
			struct sdsgx_ioctl_create __user *ubuf )
{
    struct sdsgx_ioctl_create buf;
    if (copy_from_user(&buf, ubuf, sizeof(buf)))
		return EFAULT;

    memcpy(member_sdsgx_device->shared_memory.ptr, ubuf, sizeof(buf));

    /* printk("CREATE enclave phys_addr: %llx", buf.phys_addr); */
    struct hvc_res res;
    sdsgx_hvc(HC_ENCLAVE_CREATE, buf.eid, buf.phys_addr, 0, &res);
    buf.eid = res.x1;
    /* printk("CREATE got id %u", buf.eid); */


    uintptr_t data_va_start = current->mm->start_data;
    uintptr_t data_va_end = current->mm->end_data;
    unsigned long i = 0;
    unsigned long phys_addr;

#define OPTIMIZE_INIT
#ifdef OPTIMIZE_INIT
    /* enclave will likely access this memory regions so let's map them ahead
     * of time */
    for (i = data_va_start; i < data_va_end; i+=PAGE_SIZE) {
	phys_addr = virt_to_phys_user(i);
	printk("data rgn phys_addr: %llx virt_addr: %llx\n", phys_addr, i);
	sdsgx_hvc(HC_ENCLAVE_ADD_RGN, buf.eid, phys_addr, i, &res);
    }
    uintptr_t stack_start = current->mm->start_stack;
    /* stack grows towards zero */
    for (i = stack_start; i > (stack_start - PAGE_SIZE); i-=PAGE_SIZE) {
	phys_addr = virt_to_phys_user(i);
	printk("stack rgn phys_addr: %llx virt_addr: %llx\n", phys_addr, i);
	sdsgx_hvc(HC_ENCLAVE_ADD_RGN, buf.eid, phys_addr, i, &res);
    }

    uintptr_t heap_start = current->mm->start_brk;
    uintptr_t heap_end = current->mm->brk;
    for (i = heap_start; i < heap_end; i+=PAGE_SIZE) {
	phys_addr = virt_to_phys_user(i);
	if(phys_addr == NULL)
	    continue;
	printk("heap rgn phys_addr: %llx virt_addr: %llx\n", phys_addr, i);
	sdsgx_hvc(HC_ENCLAVE_ADD_RGN, buf.eid, phys_addr, i, &res);
    }
#endif

    copy_to_user(ubuf, &buf, sizeof(buf));

    return 0;
}


#include <asm/asm-offsets.h>

int sdsgx_ecall(struct sdsgx_device *member_sdsgx_device,
			struct sdsgx_ioctl_ecall __user *ubuf)
{
    int i;
    volatile int x;
    struct sdsgx_ioctl_ecall buf;
    if (copy_from_user(&buf, ubuf, sizeof(buf)))
		return EFAULT;
    if (copy_from_user(member_sdsgx_device->shared_memory.ptr, ubuf, sizeof(buf)))
		return EFAULT;

    struct hvc_res res;
    sdsgx_hvc(HC_ENCLAVE_ECALL, buf.in.eid, sdsgx_ECALL, buf.in.sp, &res);


    if(res.x0 == sdsgx_OCALL){
	memcpy(&buf, member_sdsgx_device->shared_memory.ptr, sizeof(buf));
	buf.out.calloc_size = res.x2;
    } else if(res.x0 == sdsgx_FAULT){
	buf.out.fault_addr = res.x2;
    }

    buf.out.ret = res.x0;

    copy_to_user(ubuf, &buf, sizeof(buf));

    return 0;
}

int sdsgx_resume(struct sdsgx_device *member_sdsgx_device,
			struct sdsgx_ioctl_ecall __user *ubuf)
{    int i;
    struct sdsgx_ioctl_ecall buf;
    struct hvc_res res;
    if (copy_from_user(&buf, ubuf, sizeof(buf)))
		return EFAULT;

    uint64_t sp_el0; // needed for sgx_ocalloc...

    sdsgx_hvc(HC_ENCLAVE_RESUME, buf.in.eid, buf.in.sp, 0, &res);

    if(res.x0 == sdsgx_OCALL){
	memcpy(&buf, member_sdsgx_device->shared_memory.ptr, sizeof(buf));
	buf.out.calloc_size = res.x2;
    } else if(res.x0 == sdsgx_FAULT){
	buf.out.fault_addr = res.x2;
    }

    buf.out.ret = res.x0;
    copy_to_user(ubuf, &buf, sizeof(buf));

    return 0;
}


static int  sdsgx_destroy(struct sdsgx_device *member_sdsgx_device,
			struct sdsgx_ioctl_ecall __user *ubuf)
{
    struct sdsgx_ioctl_ecall buf;
    if (copy_from_user(&buf, ubuf, sizeof(buf)))
		return EFAULT;
    if (copy_from_user(member_sdsgx_device->shared_memory.ptr, ubuf, sizeof(buf)))
		return EFAULT;

    struct hvc_res res;
    /* printk("Destroying enclave"); */
    sdsgx_hvc(HC_ENCLAVE_DELETE, buf.in.eid, 0, 0, &res);
    return 0;
}
static int sdsgx_add_rgn(struct sdsgx_device *member_sdsgx_device,
			struct sdsgx_ioctl_add_rgn __user *ubuf)
{
    struct sdsgx_ioctl_add_rgn buf;
    if (copy_from_user(&buf, ubuf, sizeof(buf)))
	return -EFAULT;

    uint64_t phys_addr = 0;

    phys_addr = virt_to_phys_user(buf.virt_addr);

    /* printk("rgn phys_addr: %llx virt_addr: %llx\n", phys_addr, buf.virt_addr); */
    struct hvc_res res;
    sdsgx_hvc(HC_ENCLAVE_ADD_RGN, buf.eid, phys_addr, buf.virt_addr, &res);

    return 0;
}

struct sdsgx_ioctl_info{
    unsigned long calls;
    unsigned long resumes;
    unsigned long irqs;
};

static void sdsgx_info(struct sdsgx_device *member_sdsgx_device,
			struct sdsgx_ioctl_info __user *ubuf)
{
    struct sdsgx_ioctl_info buf;
    struct hvc_res res;

    sdsgx_hvc(HC_ENCLAVE_INFO, 0, 0, 0, &res);

    buf.calls = res.x1;
    buf.resumes = res.x2;
    buf.irqs = res.x3;
    copy_to_user(ubuf, &buf, sizeof(buf));
}

static long
_sdsgx_device_ioctl(struct sdsgx_device *member_sdsgx_device,
			 unsigned int cmd, unsigned long arg)
{
	volatile int x;
	void __user *uarg = (void __user *)arg;
	struct hvc_res res;

	switch (cmd) { //sdsgx create, distroy...
	case sdsgx_DEVICE_IOC_RING:
		sdsgx_hvc(
			/*hvc_id for bao*/ 0x10000,
			/* shared_memory_id */ member_sdsgx_device->id, 0,
			0, &res);
		break;
	case sdsgx_DEVICE_IOC_READ:
		member_sdsgx_device->data_available = 0;
		break;
	case sdsgx_DEVICE_IOC_CREATE_CMA: //fazer aqui a alocação da enclave com o cma
		sdsgx_create(member_sdsgx_device, uarg);
		break;
	case sdsgx_DEVICE_IOC_CALL_ENCLAVE:
		sdsgx_ecall(member_sdsgx_device, uarg);
		break;
	case sdsgx_DEVICE_IOC_RESUME_ENCLAVE:
		sdsgx_resume(member_sdsgx_device, uarg);
		break;
	case sdsgx_DEVICE_IOC_DESTROY_ENCLAVE:
		sdsgx_destroy(member_sdsgx_device, uarg);
		break;
	case sdsgx_DEVICE_IOC_ADD_RGN:
		sdsgx_add_rgn(member_sdsgx_device, uarg);
		break;
	case sdsgx_DEVICE_IOC_PRINT_INFO:
		sdsgx_info(member_sdsgx_device, uarg);
		break;
	default:
		return -1;
	}

	return 0;
}

long sdsgx_device_ioctl(struct file *filp, unsigned int cmd,
				    unsigned long arg)
{
	struct sdsgx_device *member_sdsgx_device = filp->private_data;
	_sdsgx_device_ioctl(member_sdsgx_device, cmd, arg);
	return 0;
}
EXPORT_SYMBOL(sdsgx_device_ioctl);

static struct file_operations sdsgx_device_file_operations = {
	.owner = THIS_MODULE,
	.read = sdsgx_device_read,
	.write = sdsgx_device_write,
	.open = sdsgx_device_open,
	.unlocked_ioctl = sdsgx_device_ioctl,
	.release = sdsgx_device_release
};

static int bao_ipc_irq_init(struct sdsgx_device *member_sdsgx_device)
{
	int ret = -1;
	if ((ret = request_irq(member_sdsgx_device->irq,
			       sdsgx_irq_handler, IRQF_SHARED,
			       "bao_irq_handler", member_sdsgx_device))) {
		pr_err("cannot register IRQ:%d err: %d\n",
		       member_sdsgx_device->irq, ret);
		return -EIO;
	}

	pr_info("registered for IRQ %d\n", member_sdsgx_device->irq);

	return 0;
}

static int setup_shared_memory(struct sdsgx_device *sdsgx)
{
	sdsgx->shared_memory.ptr =
		phys_to_virt(sdsgx->shared_memory.base);
	pr_info("phys_to_virt %llx: %llx\n", sdsgx->shared_memory.base,
		(long long unsigned int)(sdsgx->shared_memory.ptr));

	return 0;
}

int sdsgx_device_register(const char *label, unsigned int id,
			       unsigned int irq, uint64_t base, uint64_t size,
			       struct module *owner, struct device *parent)
{
	struct sdsgx_device *member_sdsgx_device;
	dev_t devt;
	int ret;

	/* First check if we are allocating a valid device... */
	if (id >= MAX_DEVICES) {
		pr_err("invalid id %d\n", id);
		return -EINVAL;
	}
	pr_info("Initializing %s:%d\n", label, id);
	member_sdsgx_device = &sdsgx_array[id];

	/* ... then check if we have not busy id */
	if (member_sdsgx_device->busy) {
		pr_err("id %d\n is busy", id);
		return -EBUSY;
	}

	/* Create the device and initialize its data */
	cdev_init(&member_sdsgx_device->cdev,
		  &sdsgx_device_file_operations);
	member_sdsgx_device->cdev.owner = owner;

	devt = MKDEV(MAJOR(sdsgx_device_dev_t), id);
	ret = cdev_add(&member_sdsgx_device->cdev, devt, 1);
	if (ret) {
		pr_err("failed to add char device %s at %d:%d\n", label,
		       MAJOR(sdsgx_device_dev_t), id);
		return ret;
	}

	member_sdsgx_device->dev = device_create(
		cl, parent, devt, member_sdsgx_device, "%s@%d", label, id);
	if (IS_ERR(member_sdsgx_device->dev)) {
		pr_err("unable to create device %s\n", label);
		ret = PTR_ERR(member_sdsgx_device->dev);
		goto del_cdev;
	}
	dev_set_drvdata(member_sdsgx_device->dev,
			member_sdsgx_device);

	/* Init the bao data */
	member_sdsgx_device->id = id;
	member_sdsgx_device->busy = 1;
	member_sdsgx_device->irq = irq;
	member_sdsgx_device->data_available = 0;
	member_sdsgx_device->shared_memory.base = base;
	member_sdsgx_device->shared_memory.size = size;

	strncpy(member_sdsgx_device->label, label, NAME_LEN);
	memset(member_sdsgx_device->buf, 0, BUF_LEN);

	setup_shared_memory(member_sdsgx_device);

	/* Init the wait queue */
	init_waitqueue_head(&member_sdsgx_device->queue);

	bao_ipc_irq_init(member_sdsgx_device);

	pr_info("sdsgx %s with id %u; irq %ul; base: %llx; size %lu; added\n",
		member_sdsgx_device->label, member_sdsgx_device->id,
		member_sdsgx_device->irq,
		member_sdsgx_device->shared_memory.base,
		member_sdsgx_device->shared_memory.size);

	return 0;

del_cdev:
	cdev_del(&member_sdsgx_device->cdev);

	return ret;
}

int sdsgx_device_unregister(const char *label, unsigned int id)
{
	struct sdsgx_device *member_sdsgx_device;

	/* First check if we are deallocating a valid device... */
	if (id >= MAX_DEVICES) {
		pr_err("invalid id %d\n", id);
		return -EINVAL;
	}
	member_sdsgx_device = &sdsgx_array[id];

	/* ... then check if device is actualy allocated */
	if (!member_sdsgx_device->busy ||
	    strcmp(member_sdsgx_device->label, label)) {
		pr_err("id %d is not busy or label %s is not known\n", id,
		       label);
		return -EINVAL;
	}

	/* Deinit the bao data */
	member_sdsgx_device->id = 0;
	member_sdsgx_device->busy = 0;

	disable_irq(member_sdsgx_device->irq);
	free_irq(member_sdsgx_device->irq, &member_sdsgx_device->irq);

	iounmap(member_sdsgx_device->shared_memory.resource);

	release_mem_region(member_sdsgx_device->shared_memory.base,
			   member_sdsgx_device->shared_memory.size);

	dev_info(member_sdsgx_device->dev, "bao %s with id %d removed\n",
		 label, id);

	/* Dealocate the device */
	device_destroy(cl, member_sdsgx_device->dev->devt);
	cdev_del(&member_sdsgx_device->cdev);

	return 0;
}

/* Module */

static int __init sdsgx_device_init(void)
{
	int ret;
	/* ls /sys/class */
	pr_info("preparing /sys/class \n");
	if ((cl = class_create(THIS_MODULE, SDSGX_DEVICE_NAME "_sys")) ==
	    NULL) //$ls /sys/class
	{
		ret = -1;
		pr_err("unable to class_create " SDSGX_DEVICE_NAME
		       " device! Error %p\n",
		       cl);
		return ret;
	}

	/* proc/devices */
	pr_info("preparing /proc/devices \n");
	ret = alloc_chrdev_region(&sdsgx_device_dev_t, 0, MAX_DEVICES,
				  SDSGX_DEVICE_NAME "_proc");
	if (ret < 0) {
		pr_err("unable to alloc_chrdev_region " SDSGX_DEVICE_NAME
		       " device! Error %d\n",
		       ret);
		return ret;
	}
	pr_info("got major %d\n", MAJOR(sdsgx_device_dev_t));

	pr_info(SDSGX_DEVICE_NAME " initialized\n");
	return 0;
}

static void __exit sdsgx_device_exit(void)
{
	unregister_chrdev(sdsgx_device_dev_t, SDSGX_DEVICE_NAME);
	class_destroy(cl);
}

module_init(sdsgx_device_init);
module_exit(sdsgx_device_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Garou");
MODULE_DESCRIPTION("sdsgx driver");
