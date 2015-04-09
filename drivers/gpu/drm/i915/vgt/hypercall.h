/*
 * Interface abstraction for hypervisor services
 *
 * Copyright(c) 2014 Intel Corporation. All rights reserved.
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

#ifndef _VGT_HYPERCALL_H_
#define _VGT_HYPERCALL_H_

struct guest_page;
struct vgt_device;
struct kernel_dm {
	unsigned long (*g2m_pfn)(int vm_id, unsigned long g_pfn);
	int (*pause_domain)(int vm_id);
	int (*shutdown_domain)(int vm_id);
	int (*map_mfn_to_gpfn)(int vm_id, unsigned long gpfn,
		unsigned long mfn, int nr, int map);
	int (*set_trap_area)(struct vgt_device *vgt, uint64_t start, uint64_t end, bool map);
	bool (*set_wp_pages)(struct vgt_device *vgt, struct guest_page *p);
	bool (*unset_wp_pages)(struct vgt_device *vgt, struct guest_page *p);
	int (*check_host)(void);
	int (*from_virt_to_mfn)(void *addr);
	void *(*from_mfn_to_virt)(int mfn);
	int (*inject_msi)(int vm_id, u32 addr, u16 data);
	int (*hvm_init)(struct vgt_device *vgt);
	void (*hvm_exit)(struct vgt_device *vgt);
	void *(*gpa_to_va)(struct vgt_device *vgt, unsigned long gap);
	bool (*read_va)(struct vgt_device *vgt, void *va, void *val, int len, int atomic);
	bool (*write_va)(struct vgt_device *vgt, void *va, void *val, int len, int atomic);
};

#endif /* _VGT_HYPERCALL_H_ */
