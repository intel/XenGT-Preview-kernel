/*
 * Interfaces coupled to Xen
 *
 * Copyright(c) 2011-2013 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>

#include <xen/xen-ops.h>
#include <xen/interface/memory.h>
#include <xen/interface/hvm/params.h>

#include "vgt.h"

/* Translate from VM's guest pfn to machine pfn */
unsigned long g2m_pfn(int vm_id, unsigned long g_pfn)
{
	struct xen_get_mfn_from_pfn pfn_arg;
	int rc;
	unsigned long pfn_list[1];

	pfn_list[0] = g_pfn;

	set_xen_guest_handle(pfn_arg.pfn_list, pfn_list);
	pfn_arg.nr_pfns = 1;
	pfn_arg.domid = vm_id;

	rc = HYPERVISOR_memory_op(XENMEM_get_mfn_from_pfn, &pfn_arg);
	if(rc < 0){
		vgt_err("failed to get mfn for gpfn(0x%lx)\n, errno=%d\n", g_pfn,rc);
		return INVALID_MFN;
	}

	return pfn_list[0];
}

int vgt_get_hvm_max_gpfn(int vm_id)
{
	domid_t dom_id = vm_id;
	int max_gpfn = HYPERVISOR_memory_op(XENMEM_maximum_gpfn, &dom_id);
	BUG_ON(max_gpfn < 0);
	return max_gpfn;
}

int vgt_hvm_enable (struct vgt_device *vgt)
{
	struct xen_hvm_vgt_enable vgt_enable;
	int rc;

	vgt_enable.domid = vgt->vm_id;

	rc = HYPERVISOR_hvm_op(HVMOP_vgt_enable, &vgt_enable);
	if (rc != 0)
		printk(KERN_ERR "Enable HVM vgt fail with %d!\n", rc);

	return rc;
}

int vgt_pause_domain(struct vgt_device *vgt)
{
	int rc;
	struct xen_domctl domctl;

	domctl.domain = (domid_t)vgt->vm_id;
	domctl.cmd = XEN_DOMCTL_pausedomain;
	domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	rc = HYPERVISOR_domctl(&domctl);
	if (rc != 0)
		vgt_err("HYPERVISOR_domctl pausedomain fail with %d!\n", rc);

	return rc;
}

void vgt_shutdown_domain(struct vgt_device *vgt)
{
	int rc;
	struct sched_remote_shutdown r;

	r.reason = SHUTDOWN_crash;
	r.domain_id = vgt->vm_id;
	rc = HYPERVISOR_sched_op(SCHEDOP_remote_shutdown, &r);
	if (rc != 0)
		vgt_err("failed to HYPERVISOR_sched_op\n");
}

int vgt_hvm_opregion_map(struct vgt_device *vgt, int map)
{
	void *opregion;
	struct xen_hvm_vgt_map_mmio memmap;
	int rc;
	int i;

	opregion = vgt->state.opregion_va;

	memset(&memmap, 0, sizeof(memmap));
	for (i = 0; i < VGT_OPREGION_PAGES; i++) {

		memmap.first_gfn = vgt->state.opregion_gfn[i];
		memmap.first_mfn = virt_to_mfn(opregion + i*PAGE_SIZE);
		memmap.nr_mfns = 1;
		memmap.map = map;
		memmap.domid = vgt->vm_id;
		rc = HYPERVISOR_hvm_op(HVMOP_vgt_map_mmio, &memmap);
		if (rc != 0)
			vgt_err("vgt_hvm_map_opregion fail with %d!\n", rc);
	}

	return rc;
}

/*
 * Map the aperture space (BAR1) of vGT device for direct access.
 */
int vgt_hvm_map_aperture (struct vgt_device *vgt, int map)
{
	char *cfg_space = &vgt->state.cfg_space[0];
	uint64_t bar_s;
	struct xen_hvm_vgt_map_mmio memmap;
	int r;

	if (!vgt_pci_mmio_is_enabled(vgt))
		return 0;

	/* guarantee the sequence of map -> unmap -> map -> unmap */
	if (map == vgt->state.bar_mapped[1])
		return 0;

	cfg_space += VGT_REG_CFG_SPACE_BAR1;	/* APERTUR */
	if (VGT_GET_BITS(*cfg_space, 2, 1) == 2){
		/* 64 bits MMIO bar */
		bar_s = * (uint64_t *) cfg_space;
	} else {
		/* 32 bits MMIO bar */
		bar_s = * (uint32_t*) cfg_space;
	}

	memmap.first_gfn = (bar_s + vgt_aperture_offset(vgt)) >> PAGE_SHIFT;
	memmap.first_mfn = vgt_aperture_base(vgt) >> PAGE_SHIFT;
	if (!vgt->ballooning)
		memmap.nr_mfns = vgt->state.bar_size[1] >> PAGE_SHIFT;
	else
		memmap.nr_mfns = vgt_aperture_sz(vgt) >> PAGE_SHIFT;

	memmap.map = map;
	memmap.domid = vgt->vm_id;

	printk("%s: domid=%d gfn_s=0x%llx mfn_s=0x%llx nr_mfns=0x%x\n", map==0? "remove_map":"add_map",
			vgt->vm_id, memmap.first_gfn, memmap.first_mfn, memmap.nr_mfns);

	r = HYPERVISOR_hvm_op(HVMOP_vgt_map_mmio, &memmap);

	if (r != 0)
		printk(KERN_ERR "vgt_hvm_map_aperture fail with %d!\n", r);
	else
		vgt->state.bar_mapped[1] = map;

	return r;
}

int vgt_io_trap(struct xen_domctl *ctl)
{
	int r;

	ctl->cmd = XEN_DOMCTL_vgt_io_trap;
	ctl->interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	r = HYPERVISOR_domctl(ctl);
	if (r) {
		printk(KERN_ERR "%s(): HYPERVISOR_domctl fail: %d\n", __func__, r);
		return r;
	}

	return 0;
}

/*
 * Zap the GTTMMIO bar area for vGT trap and emulation.
 */
int vgt_hvm_set_trap_area(struct vgt_device *vgt)
{
	struct xen_domctl domctl;
	struct xen_domctl_vgt_io_trap *info = &domctl.u.vgt_io_trap;

	char *cfg_space = &vgt->state.cfg_space[0];
	uint64_t bar_s, bar_e;

	int r;

	if (!vgt_pci_mmio_is_enabled(vgt))
		return 0;

	domctl.domain = vgt->vm_id;
	domctl.cmd = XEN_DOMCTL_vgt_io_trap;
	domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	info->n_pio = 0;
	info->n_mmio = 1;

	cfg_space += VGT_REG_CFG_SPACE_BAR0;
	if (VGT_GET_BITS(*cfg_space, 2, 1) == 2) {
		/* 64 bits MMIO bar */
		bar_s = * (uint64_t *) cfg_space;
	} else {
		/* 32 bits MMIO bar */
		bar_s = * (uint32_t*) cfg_space;
	}

	bar_s &= ~0xF; /* clear the LSB 4 bits */
	bar_e = bar_s + vgt->state.bar_size[0] - 1;

	info->mmio[0].s = bar_s;
	info->mmio[0].e = bar_e;

	r = HYPERVISOR_domctl(&domctl);
	if (r) {
		printk(KERN_ERR "VGT: %s(): fail to trap area: %d.\n", __func__, r);
		return r;
	}

	return r;
}

int xen_get_nr_vcpu(int vm_id)
{
	struct xen_domctl arg;
	int rc;

	arg.domain = vm_id;
	arg.cmd = XEN_DOMCTL_getdomaininfo;
	arg.interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	rc = HYPERVISOR_domctl(&arg);
	if (rc<0){
		printk(KERN_ERR "HYPERVISOR_domctl fail ret=%d\n",rc);
		/* assume it is UP */
		return 1;
	}

	return arg.u.getdomaininfo.max_vcpu_id + 1;
}

int hvm_get_parameter_by_dom(domid_t domid, int idx, uint64_t *value)
{
	struct xen_hvm_param xhv;
	int r;

	xhv.domid = domid;
	xhv.index = idx;
	r = HYPERVISOR_hvm_op(HVMOP_get_param, &xhv);
	if (r < 0) {
		printk(KERN_ERR "Cannot get hvm parameter %d: %d!\n",
			idx, r);
		return r;
	}
	*value = xhv.value;
	return r;
}

struct vm_struct *map_hvm_iopage(struct vgt_device *vgt)
{
	uint64_t ioreq_pfn;
	int rc;

	rc =hvm_get_parameter_by_dom(vgt->vm_id, HVM_PARAM_IOREQ_PFN, &ioreq_pfn);
	if (rc < 0)
		return NULL;

	return xen_remap_domain_mfn_range_in_kernel(ioreq_pfn, 1, vgt->vm_id);
}

int vgt_hvm_vmem_init(struct vgt_device *vgt)
{
	unsigned long i, j, gpfn, count;
	unsigned long nr_low_1mb_bkt, nr_high_bkt, nr_high_4k_bkt;

	/* Dom0 already has mapping for itself */
	ASSERT(vgt->vm_id != 0)

	ASSERT(vgt->vmem_vma == NULL && vgt->vmem_vma_low_1mb == NULL);

	vgt->vmem_sz = vgt_get_hvm_max_gpfn(vgt->vm_id) + 1;
	vgt->vmem_sz <<= PAGE_SHIFT;

	/* warn on non-1MB-aligned memory layout of HVM */
	if (vgt->vmem_sz & ~VMEM_BUCK_MASK)
		vgt_warn("VM%d: vmem_sz=0x%llx!\n", vgt->vm_id, vgt->vmem_sz);

	nr_low_1mb_bkt = VMEM_1MB >> PAGE_SHIFT;
	nr_high_bkt = (vgt->vmem_sz >> VMEM_BUCK_SHIFT);
	nr_high_4k_bkt = (vgt->vmem_sz >> PAGE_SHIFT);

	vgt->vmem_vma_low_1mb =
		kmalloc(sizeof(*vgt->vmem_vma) * nr_low_1mb_bkt, GFP_KERNEL);
	vgt->vmem_vma =
		kmalloc(sizeof(*vgt->vmem_vma) * nr_high_bkt, GFP_KERNEL);
	vgt->vmem_vma_4k =
		vzalloc(sizeof(*vgt->vmem_vma) * nr_high_4k_bkt);

	if (vgt->vmem_vma_low_1mb == NULL || vgt->vmem_vma == NULL ||
		vgt->vmem_vma_4k == NULL) {
		vgt_err("Insufficient memory for vmem_vma, vmem_sz=0x%llx\n",
				vgt->vmem_sz );
		goto err;
	}

	/* map the low 1MB memory */
	for (i = 0; i < nr_low_1mb_bkt; i++) {
		vgt->vmem_vma_low_1mb[i] =
			xen_remap_domain_mfn_range_in_kernel(i, 1, vgt->vm_id);

		if (vgt->vmem_vma[i] != NULL)
			continue;

		/* Don't warn on [0xa0000, 0x100000): a known non-RAM hole */
		if (i < (0xa0000 >> PAGE_SHIFT))
			vgt_dbg(VGT_DBG_GENERIC, "vGT: VM%d: can't map GPFN %ld!\n",
				vgt->vm_id, i);
	}

	printk("start vmem_map\n");
	count = 0;
	/* map the >1MB memory */
	for (i = 1; i < nr_high_bkt; i++) {
		gpfn = i << (VMEM_BUCK_SHIFT - PAGE_SHIFT);
		vgt->vmem_vma[i] = xen_remap_domain_mfn_range_in_kernel(
				gpfn,
				VMEM_BUCK_SIZE >> PAGE_SHIFT,
				vgt->vm_id);

		if (vgt->vmem_vma[i] != NULL)
			continue;


		/* for <4G GPFNs: skip the hole after low_mem_max_gpfn */
		if (gpfn < (1 << (32 - PAGE_SHIFT)) &&
			vgt->low_mem_max_gpfn != 0 &&
			gpfn > vgt->low_mem_max_gpfn)
			continue;

		for (j = gpfn;
		     j < ((i + 1) << (VMEM_BUCK_SHIFT - PAGE_SHIFT));
		     j++) {
			vgt->vmem_vma_4k[j] =
				xen_remap_domain_mfn_range_in_kernel(
					j, 1, vgt->vm_id);

			if (vgt->vmem_vma_4k[j]) {
				count++;
				vgt_dbg(VGT_DBG_GENERIC, "map 4k gpa (%lx)\n", j << PAGE_SHIFT);
			}
		}

		/* To reduce the number of err messages(some of them, due to
		 * the MMIO hole, are spurious and harmless) we only print a
		 * message if it's at every 64MB boundary or >4GB memory.
		 */
		if ((i % 64 == 0) || (i >= (1ULL << (32 - VMEM_BUCK_SHIFT))))
			vgt_dbg(VGT_DBG_GENERIC, "vGT: VM%d: can't map %ldKB\n",
				vgt->vm_id, i);
	}
	printk("end vmem_map (%ld 4k mappings)\n", count);

	return 0;
err:
	kfree(vgt->vmem_vma);
	kfree(vgt->vmem_vma_low_1mb);
	vfree(vgt->vmem_vma_4k);
	vgt->vmem_vma = vgt->vmem_vma_low_1mb = vgt->vmem_vma_4k = NULL;
	return -ENOMEM;
}

void vgt_vmem_destroy(struct vgt_device *vgt)
{
	int i, j;
	unsigned long nr_low_1mb_bkt, nr_high_bkt, nr_high_bkt_4k;

	if(vgt->vm_id == 0)
		return;

	/*
	 * Maybe the VM hasn't accessed GEN MMIO(e.g., still in the legacy VGA
	 * mode), so no mapping is created yet.
	 */
	if (vgt->vmem_vma == NULL && vgt->vmem_vma_low_1mb == NULL)
		return;

	ASSERT(vgt->vmem_vma != NULL && vgt->vmem_vma_low_1mb != NULL);

	nr_low_1mb_bkt = VMEM_1MB >> PAGE_SHIFT;
	nr_high_bkt = (vgt->vmem_sz >> VMEM_BUCK_SHIFT);
	nr_high_bkt_4k = (vgt->vmem_sz >> PAGE_SHIFT);

	for (i = 0; i < nr_low_1mb_bkt; i++) {
		if (vgt->vmem_vma_low_1mb[i] == NULL)
			continue;
		xen_unmap_domain_mfn_range_in_kernel(
			vgt->vmem_vma_low_1mb[i], 1, vgt->vm_id);
	}

	for (i = 1; i < nr_high_bkt; i++) {
		if (vgt->vmem_vma[i] == NULL) {
			for (j = (i << (VMEM_BUCK_SHIFT - PAGE_SHIFT));
			     j < ((i + 1) << (VMEM_BUCK_SHIFT - PAGE_SHIFT));
			     j++) {
				if (vgt->vmem_vma_4k[j] == NULL)
					continue;
				xen_unmap_domain_mfn_range_in_kernel(
					vgt->vmem_vma_4k[j], 1, vgt->vm_id);
			}
			continue;
		}
		xen_unmap_domain_mfn_range_in_kernel(
			vgt->vmem_vma[i], VMEM_BUCK_SIZE >> PAGE_SHIFT,
			vgt->vm_id);
	}

	kfree(vgt->vmem_vma);
	kfree(vgt->vmem_vma_low_1mb);
	vfree(vgt->vmem_vma_4k);
}

void* vgt_vmem_gpa_2_va(struct vgt_device *vgt, unsigned long gpa)
{
	unsigned long buck_index, buck_4k_index;

	if (vgt->vm_id == 0)
		return (char*)mfn_to_virt(gpa>>PAGE_SHIFT) + (gpa & (PAGE_SIZE-1));

	/*
	 * At the beginning of _hvm_mmio_emulation(), we already initialize
	 * vgt->vmem_vma and vgt->vmem_vma_low_1mb.
	 */
	ASSERT(vgt->vmem_vma != NULL && vgt->vmem_vma_low_1mb != NULL);

	/* handle the low 1MB memory */
	if (gpa < VMEM_1MB) {
		buck_index = gpa >> PAGE_SHIFT;
		if (!vgt->vmem_vma_low_1mb[buck_index])
			return NULL;

		return (char*)(vgt->vmem_vma_low_1mb[buck_index]->addr) +
			(gpa & ~PAGE_MASK);

	}

	/* handle the >1MB memory */
	buck_index = gpa >> VMEM_BUCK_SHIFT;

	if (!vgt->vmem_vma[buck_index]) {
		buck_4k_index = gpa >> PAGE_SHIFT;
		if (!vgt->vmem_vma_4k[buck_4k_index]) {
			if (buck_4k_index > vgt->low_mem_max_gpfn)
				vgt_err("vGT failed to map gpa=0x%lx?\n", gpa);
			return NULL;
		}

		return (char*)(vgt->vmem_vma_4k[buck_4k_index]->addr) +
			(gpa & ~PAGE_MASK);
	}

	return (char*)(vgt->vmem_vma[buck_index]->addr) +
		(gpa & (VMEM_BUCK_SIZE -1));
}

