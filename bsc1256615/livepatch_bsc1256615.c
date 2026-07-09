/*
 * livepatch_bsc1256615
 *
 * Fix for CVE-2025-71089, bsc#1256615
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_IOMMU_SVA)

#include "livepatch_bsc1256615.h"


/* klp-ccp: from drivers/iommu/iommu-sva.c */
#include <linux/mmu_context.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/iommu.h>

/* klp-ccp: from include/linux/iommu.h */
#ifdef CONFIG_IOMMU_MM_DATA

struct iommu_sva *klpp_iommu_sva_bind_device(struct device *dev,
					struct mm_struct *mm);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_IOMMU_SVA */

/* klp-ccp: from drivers/iommu/iommu-priv.h */
#include <linux/iommu.h>

static inline const struct iommu_ops *dev_iommu_ops(struct device *dev)
{
	/*
	 * Assume that valid ops must be installed if iommu_probe_device()
	 * has succeeded. The device ops are essentially for internal use
	 * within the IOMMU subsystem itself, so we should be able to trust
	 * ourselves not to misuse the helper.
	 */
	return dev->iommu->iommu_dev->ops;
}

struct iommu_attach_handle *iommu_attach_handle_get(struct iommu_group *group,
						    ioasid_t pasid,
						    unsigned int type);

/* klp-ccp: from drivers/iommu/iommu-sva.c */
extern struct mutex iommu_sva_lock;
static struct iommu_domain *iommu_sva_domain_alloc(struct device *dev,
						   struct mm_struct *mm);

static struct iommu_mm_data *iommu_alloc_mm_data(struct mm_struct *mm, struct device *dev)
{
	struct iommu_mm_data *iommu_mm;
	ioasid_t pasid;

	lockdep_assert_held(&iommu_sva_lock);

	if (!arch_pgtable_dma_compat(mm))
		return ERR_PTR(-EBUSY);

	iommu_mm = mm->iommu_mm;
	/* Is a PASID already associated with this mm? */
	if (iommu_mm) {
		if (iommu_mm->pasid >= dev->iommu->max_pasids)
			return ERR_PTR(-EOVERFLOW);
		return iommu_mm;
	}

	iommu_mm = kzalloc(sizeof(struct iommu_mm_data), GFP_KERNEL);
	if (!iommu_mm)
		return ERR_PTR(-ENOMEM);

	pasid = iommu_alloc_global_pasid(dev);
	if (pasid == IOMMU_PASID_INVALID) {
		kfree(iommu_mm);
		return ERR_PTR(-ENOSPC);
	}
	iommu_mm->pasid = pasid;
	INIT_LIST_HEAD(&iommu_mm->sva_domains);
	/*
	 * Make sure the write to mm->iommu_mm is not reordered in front of
	 * initialization to iommu_mm fields. If it does, readers may see a
	 * valid iommu_mm with uninitialized values.
	 */
	smp_store_release(&mm->iommu_mm, iommu_mm);
	return iommu_mm;
}

struct iommu_sva *klpp_iommu_sva_bind_device(struct device *dev, struct mm_struct *mm)
{
	struct iommu_group *group = dev->iommu_group;
	struct iommu_attach_handle *attach_handle;
	struct iommu_mm_data *iommu_mm;
	struct iommu_domain *domain;
	struct iommu_sva *handle;
	int ret;

	if (!group)
		return ERR_PTR(-ENODEV);

	if (IS_ENABLED(CONFIG_X86))
		return ERR_PTR(-EOPNOTSUPP);

	mutex_lock(&iommu_sva_lock);

	/* Allocate mm->pasid if necessary. */
	iommu_mm = iommu_alloc_mm_data(mm, dev);
	if (IS_ERR(iommu_mm)) {
		ret = PTR_ERR(iommu_mm);
		goto out_unlock;
	}

	/* A bond already exists, just take a reference`. */
	attach_handle = iommu_attach_handle_get(group, iommu_mm->pasid, IOMMU_DOMAIN_SVA);
	if (!IS_ERR(attach_handle)) {
		handle = container_of(attach_handle, struct iommu_sva, handle);
		if (attach_handle->domain->mm != mm) {
			ret = -EBUSY;
			goto out_unlock;
		}
		refcount_inc(&handle->users);
		mutex_unlock(&iommu_sva_lock);
		return handle;
	}

	if (PTR_ERR(attach_handle) != -ENOENT) {
		ret = PTR_ERR(attach_handle);
		goto out_unlock;
	}

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/* Search for an existing domain. */
	list_for_each_entry(domain, &mm->iommu_mm->sva_domains, next) {
		ret = iommu_attach_device_pasid(domain, dev, iommu_mm->pasid,
						&handle->handle);
		if (!ret) {
			domain->users++;
			goto out;
		}
	}

	/* Allocate a new domain and set it on device pasid. */
	domain = iommu_sva_domain_alloc(dev, mm);
	if (IS_ERR(domain)) {
		ret = PTR_ERR(domain);
		goto out_free_handle;
	}

	ret = iommu_attach_device_pasid(domain, dev, iommu_mm->pasid,
					&handle->handle);
	if (ret)
		goto out_free_domain;
	domain->users = 1;
	list_add(&domain->next, &mm->iommu_mm->sva_domains);

out:
	refcount_set(&handle->users, 1);
	mutex_unlock(&iommu_sva_lock);
	handle->dev = dev;
	return handle;

out_free_domain:
	iommu_domain_free(domain);
out_free_handle:
	kfree(handle);
out_unlock:
	mutex_unlock(&iommu_sva_lock);
	return ERR_PTR(ret);
}

typeof(klpp_iommu_sva_bind_device) klpp_iommu_sva_bind_device;

extern int iommu_sva_iopf_handler(struct iopf_group *group);

static struct iommu_domain *iommu_sva_domain_alloc(struct device *dev,
						   struct mm_struct *mm)
{
	const struct iommu_ops *ops = dev_iommu_ops(dev);
	struct iommu_domain *domain;

	if (ops->domain_alloc_sva) {
		domain = ops->domain_alloc_sva(dev, mm);
		if (IS_ERR(domain))
			return domain;
	} else {
		domain = ops->domain_alloc(IOMMU_DOMAIN_SVA);
		if (!domain)
			return ERR_PTR(-ENOMEM);
	}

	domain->type = IOMMU_DOMAIN_SVA;
	mmgrab(mm);
	domain->mm = mm;
	domain->owner = ops;
	domain->iopf_handler = iommu_sva_iopf_handler;

	return domain;
}


#include <linux/livepatch.h>

extern typeof(iommu_sva_iopf_handler) iommu_sva_iopf_handler
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, iommu_sva_iopf_handler);
extern typeof(iommu_sva_lock) iommu_sva_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, iommu_sva_lock);

#endif /* IS_ENABLED(CONFIG_IOMMU_SVA) */
