/*
 * livepatch_bsc1235005
 *
 * Fix for CVE-2024-53214, bsc#1235005
 *
 *  Upstream commit:
 *  fe4bf8d0b671 ("vfio/pci: Properly hide first-in-list PCIe extended capability")
 *
 *  SLE12-SP5 commit:
 *  1b7890f6142c6bc35e9e35e4c92f18dbd44c5a5e
 *
 *  SLE15-SP3 commit:
 *  bf247b69d267644c858f7f4bd9c6144f5f3a47ab
 *
 *  SLE15-SP4 and -SP5 commit:
 *  f520125d76d82c8e5e75b445b5ae21c48d05606e
 *
 *  SLE15-SP6 commit:
 *  44164cb642bab7f579ee832fbbe2108d8c731aad
 *
 *  SLE MICRO-6-0 commit:
 *  44164cb642bab7f579ee832fbbe2108d8c731aad
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* klp-ccp: from drivers/vfio/pci/vfio_pci_config.c */
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/uaccess.h>

#include <linux/slab.h>

/* klp-ccp: from drivers/vfio/pci/vfio_pci_private.h */
#include <linux/mutex.h>
#include <linux/pci.h>

#include <linux/types.h>

#define VFIO_PCI_OFFSET_SHIFT   40

#define VFIO_PCI_OFFSET_MASK	(((u64)(1) << VFIO_PCI_OFFSET_SHIFT) - 1)

#define PCI_CAP_ID_INVALID		0xFF	/* default raw access */
#define PCI_CAP_ID_INVALID_VIRT		0xFE	/* default virt access */

struct vfio_pci_device {
	struct pci_dev		*pdev;
	void __iomem		*barmap[PCI_STD_RESOURCE_END + 1];
	bool			bar_mmap_supported[PCI_STD_RESOURCE_END + 1];
	u8			*pci_config_map;
	u8			*vconfig;
	struct perm_bits	*msi_perm;
	spinlock_t		irqlock;
	struct mutex		igate;
	struct vfio_pci_irq_ctx	*ctx;
	int			num_ctx;
	int			irq_type;
	int			num_regions;
	struct vfio_pci_region	*region;
	u8			msi_qmax;
	u8			msix_bar;
	u16			msix_size;
	u32			msix_offset;
	u32			rbar[7];
	bool			pci_2_3;
	bool			virq_disabled;
	bool			reset_works;
	bool			extended_caps;
	bool			bardirty;
	bool			has_vga;
	bool			needs_reset;
	bool			nointx;
	struct pci_saved_state	*pci_saved_state;
	int			refcnt;
	struct eventfd_ctx	*err_trigger;
	struct eventfd_ctx	*req_trigger;
	struct list_head	dummy_resources_list;
	struct mutex		vma_lock;
	struct list_head	vma_list;
	struct rw_semaphore	memory_lock;
};

/* klp-ccp: from drivers/vfio/pci/vfio_pci_config.c */
#define PCI_CAP_ID_BASIC	0

struct perm_bits {
	u8	*virt;		/* read/write virtual data, not hw */
	u8	*write;		/* writeable bits */
	int	(*readfn)(struct vfio_pci_device *vdev, int pos, int count,
			  struct perm_bits *perm, int offset, __le32 *val);
	int	(*writefn)(struct vfio_pci_device *vdev, int pos, int count,
			   struct perm_bits *perm, int offset, __le32 val);
};

static int (*klpe_vfio_user_config_read)(struct pci_dev *pdev, int offset,
				 __le32 *val, int count);

static int klpp_vfio_direct_config_read(struct vfio_pci_device *vdev, int pos,
				   int count, struct perm_bits *perm,
				   int offset, __le32 *val)
{
	int ret;

	ret = (*klpe_vfio_user_config_read)(vdev->pdev, pos, val, count);
	if (ret)
		return ret;

	if (pos >= PCI_CFG_SPACE_SIZE) { /* Extended cap header mangling */
		if (offset < 4)
			memcpy(val, vdev->vconfig + pos, count);
	} else if (pos >= PCI_STD_HEADER_SIZEOF) { /* Std cap mangling */
		if (offset == PCI_CAP_LIST_ID && count > 1)
			memcpy(val, vdev->vconfig + pos,
			       min(PCI_CAP_FLAGS, count));
		else if (offset == PCI_CAP_LIST_NEXT)
			memcpy(val, vdev->vconfig + pos, 1);
	}

	return count;
}

static struct perm_bits direct_ro_perms = {
	.readfn = klpp_vfio_direct_config_read,
};

static struct perm_bits (*klpe_cap_perms)[PCI_CAP_ID_MAX + 1];
static struct perm_bits (*klpe_ecap_perms)[PCI_EXT_CAP_ID_MAX + 1];

static struct perm_bits (*klpe_unassigned_perms);

static struct perm_bits (*klpe_virt_perms);

static int vfio_find_cap_start(struct vfio_pci_device *vdev, int pos)
{
	u8 cap;
	int base = (pos >= PCI_CFG_SPACE_SIZE) ? PCI_CFG_SPACE_SIZE :
						 PCI_STD_HEADER_SIZEOF;
	cap = vdev->pci_config_map[pos];

	if (cap == PCI_CAP_ID_BASIC)
		return 0;

	/* XXX Can we have to abutting capabilities of the same type? */
	while (pos - 1 >= base && vdev->pci_config_map[pos - 1] == cap)
		pos--;

	return pos;
}

static size_t vfio_pci_cap_remaining_dword(struct vfio_pci_device *vdev,
					   loff_t pos)
{
	u8 cap = vdev->pci_config_map[pos];
	size_t i;

	for (i = 1; (pos + i) % 4 && vdev->pci_config_map[pos + i] == cap; i++)
		/* nop */;

	return i;
}

static ssize_t klpp_vfio_config_do_rw(struct vfio_pci_device *vdev, char __user *buf,
				 size_t count, loff_t *ppos, bool iswrite)
{
	struct pci_dev *pdev = vdev->pdev;
	struct perm_bits *perm;
	__le32 val = 0;
	int cap_start = 0, offset;
	u8 cap_id;
	ssize_t ret;

	if (*ppos < 0 || *ppos >= pdev->cfg_size ||
	    *ppos + count > pdev->cfg_size)
		return -EFAULT;

	/*
	 * Chop accesses into aligned chunks containing no more than a
	 * single capability.  Caller increments to the next chunk.
	 */
	count = min(count, vfio_pci_cap_remaining_dword(vdev, *ppos));
	if (count >= 4 && !(*ppos % 4))
		count = 4;
	else if (count >= 2 && !(*ppos % 2))
		count = 2;
	else
		count = 1;

	ret = count;

	cap_id = vdev->pci_config_map[*ppos];

	if (cap_id == PCI_CAP_ID_INVALID) {
		perm = &(*klpe_unassigned_perms);
		cap_start = *ppos;
	} else if (cap_id == PCI_CAP_ID_INVALID_VIRT) {
		perm = &(*klpe_virt_perms);
		cap_start = *ppos;
	} else {
		if (*ppos >= PCI_CFG_SPACE_SIZE) {
			/*
			 * We can get a cap_id that exceeds PCI_EXT_CAP_ID_MAX
			 * if we're hiding an unknown capability at the start
			 * of the extended capability list.  Use default, ro
			 * access, which will virtualize the id and next values.
			 */
			if (cap_id > PCI_EXT_CAP_ID_MAX)
				perm = &direct_ro_perms;
			else
				perm = &(*klpe_ecap_perms)[cap_id];

			cap_start = vfio_find_cap_start(vdev, *ppos);
		} else {
			WARN_ON(cap_id > PCI_CAP_ID_MAX);

			perm = &(*klpe_cap_perms)[cap_id];

			if (cap_id == PCI_CAP_ID_MSI)
				perm = vdev->msi_perm;

			if (cap_id > PCI_CAP_ID_BASIC)
				cap_start = vfio_find_cap_start(vdev, *ppos);
		}
	}

	WARN_ON(!cap_start && cap_id != PCI_CAP_ID_BASIC);
	WARN_ON(cap_start > *ppos);

	offset = *ppos - cap_start;

	if (iswrite) {
		if (!perm->writefn)
			return ret;

		if (copy_from_user(&val, buf, count))
			return -EFAULT;

		ret = perm->writefn(vdev, *ppos, count, perm, offset, val);
	} else {
		if (perm->readfn) {
			ret = perm->readfn(vdev, *ppos, count,
					   perm, offset, &val);
			if (ret < 0)
				return ret;
		}

		if (copy_to_user(buf, &val, count))
			return -EFAULT;
	}

	return ret;
}

ssize_t klpp_vfio_pci_config_rw(struct vfio_pci_device *vdev, char __user *buf,
			   size_t count, loff_t *ppos, bool iswrite)
{
	size_t done = 0;
	int ret = 0;
	loff_t pos = *ppos;

	pos &= VFIO_PCI_OFFSET_MASK;

	while (count) {
		ret = klpp_vfio_config_do_rw(vdev, buf, count, &pos, iswrite);
		if (ret < 0)
			return ret;

		count -= ret;
		done += ret;
		buf += ret;
		pos += ret;
	}

	*ppos += done;

	return done;
}


#include "livepatch_bsc1235005.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "vfio_pci"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "cap_perms", (void *)&klpe_cap_perms, "vfio_pci" },
	{ "ecap_perms", (void *)&klpe_ecap_perms, "vfio_pci" },
	{ "unassigned_perms", (void *)&klpe_unassigned_perms, "vfio_pci" },
	{ "vfio_user_config_read", (void *)&klpe_vfio_user_config_read,
	  "vfio_pci" },
	{ "virt_perms", (void *)&klpe_virt_perms, "vfio_pci" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1235005_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1235005_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
