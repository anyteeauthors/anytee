/*
 * Platform driver
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include "sdsgx.h"

static int sdsgx_device_req_probe(struct platform_device *pdev)
{
	struct device *dev = &(pdev->dev);
	struct device_node *np = dev->of_node;
	struct module *owner = THIS_MODULE;
	//const char *file;
	uint64_t base;
	uint64_t size;
	int ret = 0;
	int id;
	struct resource *r;
	int irq = -1;

	of_property_read_u32(np, "id", &id);

	/* read reserved memory base address and size */
	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	base = r->start;
	size = r->end - r->start + 1;
	pr_info("shmem.base:0%llx shmem.size:%llu", base, size);

	irq = platform_get_irq(pdev, 0);
	pr_info("irq: %d", irq);

	/* Register the new chr device */
	ret = sdsgx_device_register(SDSGX_DEVICE_NAME, id, irq, base,
					 size, owner, dev); //ver id
	if (ret) {
		pr_err("unable to register");
		return ret;
	}

	return ret;
}

static int sdsgx_device_req_remove(struct platform_device *pdev)
{
	/* thsi impleemtnation is unfinished */
	return sdsgx_device_unregister(SDSGX_DEVICE_NAME, 0);
}

static const struct of_device_id of_sdsgx_dev_req_match[] = {
	{
		.compatible = "sdsgx",
	},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_sdsgx_dev_req_match);

static struct platform_driver sdsgx_req_driver = {
    .probe = sdsgx_device_req_probe,
    .remove = sdsgx_device_req_remove,
    .driver = {
        .name = SDSGX_DEVICE_NAME,
        .of_match_table = of_sdsgx_dev_req_match,
    },
};
module_platform_driver(sdsgx_req_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Garou");
MODULE_DESCRIPTION("sdsgx driver");
