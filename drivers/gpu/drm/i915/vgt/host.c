#include <linux/io.h>
#include <drm/drmP.h>

#include "i915_drv.h"
#include "host.h"

static struct drm_i915_private *dev_priv = NULL;
static unsigned long gtt_offset = 0;

void i915_vgt_record_priv(struct drm_i915_private *priv)
{
	struct drm_device *dev = priv->dev;

	BUG_ON(!dev);

	dev_priv = priv;
	gtt_offset = pci_resource_len(dev->pdev, 0) / 2;
}

bool vgt_native_mmio_read(u32 reg, void *val, int len, bool trace)
{
	BUG_ON(!dev_priv);

	switch (len) {
		case 1:
			*(u8 *)val = dev_priv->uncore.funcs.mmio_readb(dev_priv, reg, trace);
			break;
		case 2:
			*(u16 *)val = dev_priv->uncore.funcs.mmio_readw(dev_priv, reg, trace);
			break;
		case 4:
			*(u32 *)val = dev_priv->uncore.funcs.mmio_readl(dev_priv, reg, trace);
			break;
		case 8:
			*(u64 *)val = dev_priv->uncore.funcs.mmio_readq(dev_priv, reg, trace);
			break;
		default:
			vgt_err("your len is wrong: %d\n", len);
			return false;
	}
	return true;
}

bool vgt_native_mmio_write(u32 reg, void *val, int len, bool trace)
{
	BUG_ON(!dev_priv);

	switch (len) {
		case 1:
			dev_priv->uncore.funcs.mmio_writeb(dev_priv, reg, *(u8 *)val, trace);
			break;
		case 2:
			dev_priv->uncore.funcs.mmio_writew(dev_priv, reg, *(u16 *)val, trace);
			break;
		case 4:
			dev_priv->uncore.funcs.mmio_writel(dev_priv, reg, *(u32 *)val, trace);
			break;
		case 8:
			dev_priv->uncore.funcs.mmio_writeq(dev_priv, reg, *(u64 *)val, trace);
			break;
		default:
			vgt_err("your len is wrong: %d\n", len);
			return false;
	}
	return true;
}

bool vgt_native_gtt_read(u32 reg, void *val, int len)
{
	void *va = (void *)vgt_gttmmio_va(pdev_default, reg + gtt_offset);

#if 0
	if (dev_priv && vgt_ops && vgt_ops->initialized) {
		switch (len) {
		case 4:
			*(u32 *)val = readl(reg + dev_priv->gtt.gsm);
			break;
		case 8:
			*(u64 *)val = readq(reg + dev_priv->gtt.gsm);
			break;
		default:
			vgt_err("your len is wrong: %d\n", len);
			return false;
		}
		return true;
	} else
#endif
	{
		switch (len) {
		case 4:
			*(u32 *)val = readl(va);
			break;
		case 8:
			*(u64 *)val = readq(va);
			break;
		default:
			vgt_err("your len is wrong: %d\n", len);
			return false;
		}
		return true;
	}
}

bool vgt_native_gtt_write(u32 reg, void *val, int len)
{
	void *va = (void *)vgt_gttmmio_va(pdev_default, reg + gtt_offset);

#if 0
	if (dev_priv) {
		switch (len) {
		case 4:
			writel(*(u32 *)val, reg + dev_priv->gtt.gsm);
			break;
		case 8:
			writeq(*(u64 *)val, reg + dev_priv->gtt.gsm);
			break;
		default:
			vgt_err("your len is wrong: %d\n", len);
			return false;
		}
		return true;
	} else
#endif
	{
		switch (len) {
		case 4:
			writel(*(u32 *)val, va);
			break;
		case 8:
			writeq(*(u64 *)val, va);
			break;
		default:
			vgt_err("your len is wrong: %d\n", len);
			return false;
		}
		return true;
	}
}

bool vgt_host_read(u32 reg, void *val, int len, bool is_gtt, bool trace)
{
	uint64_t pa;

	BUG_ON(!dev_priv);

	pa = is_gtt ?
		vgt_gttmmio_pa(pdev_default, reg + gtt_offset) :
		vgt_gttmmio_pa(pdev_default, reg);
	return vgt_ops->mem_read(vgt_dom0, pa, val, len);
}

bool vgt_host_write(u32 reg, void *val, int len, bool is_gtt, bool trace)
{
	uint64_t pa;

	BUG_ON(!dev_priv);

	pa = is_gtt ?
		vgt_gttmmio_pa(pdev_default, reg + gtt_offset) :
		vgt_gttmmio_pa(pdev_default, reg);
	return vgt_ops->mem_write(vgt_dom0, pa, val, len);
}

void vgt_host_irq_sync(void)
{
	irq_work_sync(&dev_priv->irq_work);
}

void vgt_host_irq(int irq)
{
	struct drm_device *dev = pci_get_drvdata(pgt_to_pci(pdev_default));
	vgt_schedule_host_isr(dev);
}

void vgt_force_wake_get(void)
{
	gen6_gt_force_wake_get(dev_priv, FORCEWAKE_ALL);
}

void vgt_force_wake_put(void)
{
	gen6_gt_force_wake_put(dev_priv, FORCEWAKE_ALL);
}
