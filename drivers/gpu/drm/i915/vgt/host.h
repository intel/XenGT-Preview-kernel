#ifndef _VGT_HOST_MEDIATE_H_
#define _VGT_HOST_MEDIATE_H_

#define vgt_info(fmt, s...)	\
	do { printk(KERN_INFO "vGT info:(%s:%d) " fmt, __FUNCTION__, __LINE__, ##s); } while (0)

#define vgt_warn(fmt, s...)	\
	do { printk(KERN_WARNING "vGT warning:(%s:%d) " fmt, __FUNCTION__, __LINE__, ##s); } while (0)

#define vgt_err(fmt, s...)	\
	do { printk(KERN_ERR "vGT error:(%s:%d) " fmt, __FUNCTION__, __LINE__, ##s); } while (0)

struct pgt_device;
struct vgt_device;
struct vgt_ops;
typedef struct {
    bool (*mem_read)(struct vgt_device *vgt, uint64_t pa, void *p_data, int bytes);
    bool (*mem_write)(struct vgt_device *vgt, uint64_t pa, void *p_data, int bytes);
    bool (*cfg_read)(struct vgt_device *vgt, unsigned int off, void *p_data, int bytes);
    bool (*cfg_write)(struct vgt_device *vgt, unsigned int off, void *p_data, int bytes);
    bool initialized;	/* whether vgt_ops can be referenced */
} vgt_ops_t;
extern struct pgt_device *pdev_default;
extern struct vgt_device *vgt_dom0;
extern vgt_ops_t *vgt_ops;

bool vgt_native_mmio_read(u32 reg, void *val, int len, bool trace);
bool vgt_native_mmio_write(u32 reg, void *val, int len, bool trace);
bool vgt_native_gtt_read(u32 reg, void *val, int len);
bool vgt_native_gtt_write(u32 reg, void *val, int len);
void vgt_host_irq(int);
void vgt_host_irq_sync(void);

void vgt_force_wake_get(void);
void vgt_force_wake_put(void);

uint64_t vgt_gttmmio_va(struct pgt_device *pdev, off_t reg);
uint64_t vgt_gttmmio_pa(struct pgt_device *pdev, off_t reg);
struct pci_dev *pgt_to_pci(struct pgt_device *pdev);

#endif /* _VGT_HOST_MEDIATE_H_ */
