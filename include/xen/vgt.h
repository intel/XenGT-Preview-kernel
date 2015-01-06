/*
 * vgt.h: core header file for vGT driver
 *
 * Copyright(c) 2011-2013 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _VGT_H_
#define _VGT_H_

#include <linux/interrupt.h>
#include <linux/sched.h>

// structures
struct vgt_device;
typedef struct {
    bool (*mem_read)(struct vgt_device *vgt, uint64_t pa, void *p_data, int bytes);
    bool (*mem_write)(struct vgt_device *vgt, uint64_t pa, void *p_data, int bytes);
    bool (*cfg_read)(struct vgt_device *vgt, unsigned int off, void *p_data, int bytes);
    bool (*cfg_write)(struct vgt_device *vgt, unsigned int off, void *p_data, int bytes);
    bool boot_time;	/* in boot time dom0 access is always passed through */
    bool initialized;	/* whether vgt_ops can be referenced */
} vgt_ops_t;
extern vgt_ops_t *vgt_ops;

/* pass through the GEN dev's pci config to Dom0 temporarily ?
 * HVM Linux DomU's invoking this function has no effect.
 */
static inline void set_gen_pci_cfg_space_pt(int enable)
{
	/* HVM Linux DomU should do nothing */
	if (vgt_ops == NULL)
		return;

	vgt_ops->boot_time = !!enable;
}

#define vgt_is_dom0(id)	(id == 0)

/* get the bits high:low of the data, high and low is starting from zero*/
#define VGT_GET_BITS(data, high, low)	(((data) & ((1 << ((high) + 1)) - 1)) >> (low))
/* get one bit of the data, bit is starting from zeor */
#define VGT_GET_BIT(data, bit)		VGT_GET_BITS(data, bit, bit)

bool vgt_emulate_write(struct vgt_device *vgt, uint64_t pa, void *p_data, int bytes);
bool vgt_emulate_read(struct vgt_device *vgt, uint64_t pa, void *p_data, int bytes);
bool vgt_emulate_cfg_write(struct vgt_device *vgt, unsigned int off, void *p_data, int bytes);
bool vgt_emulate_cfg_read(struct vgt_device *vgt, unsigned int off, void *p_data, int bytes);

// function prototype definitions
// defined in arch specific file
extern int xen_register_vgt_driver(vgt_ops_t *ops);
extern int xen_start_vgt(struct pci_dev *pdev);
extern void xen_vgt_dom0_ready(struct vgt_device *vgt);
extern void xen_deregister_vgt_device(struct vgt_device *vgt);
extern int vgt_suspend(struct pci_dev *pdev);
extern int vgt_resume(struct pci_dev *pdev);

extern int hcall_mmio_read(
        unsigned long port,
        unsigned int bytes,
        unsigned long *val);

extern int hcall_mmio_write(
        unsigned long port,
        unsigned int bytes,
        unsigned long val);

extern int hcall_vgt_ctrl(unsigned long ctrl_op);

extern int vgt_io_trap(struct xen_domctl *ctl);
/*
 * if this macro is defined, vgt will map GMA [0,64M] to the same page as [128M,192M] in GTT
 * this macro should be used together with DOM0_NON_IDENTICAL macro
 * it is only for debuging purpose
 * */
//#define DOM0_DUAL_MAP

/* save the fixed/translated guest address
 * restore the address after the command is executed
*/
#define VGT_ENABLE_ADDRESS_FIX_SAVE_RESTORE

extern bool vgt_can_process_irq(void);
extern bool vgt_can_process_timer(void *timer);
extern void vgt_new_delay_event_timer(void *timer);

DECLARE_PER_CPU(u8, in_vgt);

/*
 * in_vgt flag is used to indicate whether current code
 * path is in vgt core module, which is key for virtual
 * irq delivery in de-privileged dom0 framework. So use
 * get_cpu/put_cpu here to avoid preemption, otherwise
 * this flag loses its intention.
 */
static inline int vgt_enter(void)
{
	int cpu = get_cpu();

	per_cpu(in_vgt, cpu)++;
	return cpu;
}

extern void inject_dom0_virtual_interrupt(void *info);
static inline void vgt_exit(int cpu)
{
	per_cpu(in_vgt, cpu)--;

	/* check for delayed virq injection */
	inject_dom0_virtual_interrupt(NULL);

	put_cpu();
}

extern bool vgt_handle_dom0_device_reset(void);
// MMIO definitions

#endif	/* _VGT_H_ */
