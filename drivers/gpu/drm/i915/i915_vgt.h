#ifndef _I915_VGT_H_
#define _I915_VGT_H_

#include <linux/interrupt.h>

struct drm_device;
struct drm_i915_private;

#ifdef CONFIG_I915_VGT

bool i915_start_vgt(struct pci_dev *);
void i915_vgt_record_priv(struct drm_i915_private *priv);
bool vgt_host_read(u32, void *, int, bool, bool);
bool vgt_host_write(u32, void *, int, bool, bool);
void vgt_schedule_host_isr(struct drm_device *);
void *vgt_init_irq(struct pci_dev *, struct drm_device *);
void vgt_fini_irq(struct pci_dev *);
irqreturn_t vgt_interrupt(int, void *);
int vgt_suspend(struct pci_dev *pdev);
int vgt_resume(struct pci_dev *pdev);
bool vgt_check_host(void);

#else /* !CONFIG_I915_VGT */

static inline bool i915_start_vgt(struct pci_dev *pdev)
{
	return false;
}

static inline void i915_vgt_record_priv(struct drm_i915_private *priv)
{
}

static inline bool vgt_host_read(u32 reg, void *val, int len,
			bool is_gtt, bool trace)
{
	return false;
}

static inline bool vgt_host_write(u32 reg, void *val, int len,
			bool is_gtt, bool trace)
{
	return false;
}

static inline void *vgt_init_irq(struct pci_dev *pdev, struct drm_device *dev)
{
	return NULL;
}

static inline void vgt_fini_irq(struct pci_dev *pdev)
{
}

static inline irqreturn_t vgt_interrupt(int irq, void *data)
{
	return IRQ_NONE;
}

static inline int vgt_suspend(struct pci_dev *pdev)
{
	return 0;
}

static inline int vgt_resume(struct pci_dev *pdev)
{
	return 0;
}

static inline bool vgt_check_host(void)
{
	return false;
}

#endif /* CONFIG_I915_VGT */

#endif
