/*
 * livepatch_bsc1180008
 *
 * Fix for CVE-2020-29569, bsc#1180008
 *
 *  Upstream commit:
 *  1c728719a4da ("xen-blkback: set ring->xenblkd to NULL after kthread_stop()")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  acb25f406a00b96be456fda926c78ea7ea1ecfb7
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  1aab73c2eabdbf91096fafa92ba7d42cc74e5e85
 *
 *  SLE15-SP2 commit:
 *  552ca06fa1502102e5247945248a48ec20f691e1
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if IS_ENABLED(CONFIG_XEN_BLKDEV_BACKEND)

#if !IS_MODULE(CONFIG_XEN_BLKDEV_BACKEND)
#error "Live patch supports only CONFIG_XEN_BLKDEV_BACKEND=m"
#endif


/* klp-ccp: from drivers/block/xen-blkback/xenbus.c */
#define pr_fmt(fmt) "xen-blkback: " fmt

#include <stdarg.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <xen/events.h>
#include <xen/grant_table.h>
/* klp-ccp: from drivers/block/xen-blkback/common.h */
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/io.h>
#include <linux/rbtree.h>
#include <xen/grant_table.h>
#include <xen/page.h>
#include <xen/xenbus.h>
#include <xen/interface/io/ring.h>
#include <xen/interface/io/blkif.h>
#include <xen/interface/io/protocols.h>

#define MAX_INDIRECT_SEGMENTS 256

#define XEN_PAGES_PER_SEGMENT   (PAGE_SIZE / XEN_PAGE_SIZE)

#define XEN_PAGES_PER_INDIRECT_FRAME \
	(XEN_PAGE_SIZE/sizeof(struct blkif_request_segment))
#define SEGS_PER_INDIRECT_FRAME	\
	(XEN_PAGES_PER_INDIRECT_FRAME / XEN_PAGES_PER_SEGMENT)

#define MAX_INDIRECT_PAGES \
	((MAX_INDIRECT_SEGMENTS + SEGS_PER_INDIRECT_FRAME - 1)/SEGS_PER_INDIRECT_FRAME)

struct blkif_common_back_ring { RING_IDX rsp_prod_pvt; RING_IDX req_cons; unsigned int nr_ents; struct blkif_common_sring *sring; };

struct blkif_x86_32_back_ring { RING_IDX rsp_prod_pvt; RING_IDX req_cons; unsigned int nr_ents; struct blkif_x86_32_sring *sring; };

struct blkif_x86_64_back_ring { RING_IDX rsp_prod_pvt; RING_IDX req_cons; unsigned int nr_ents; struct blkif_x86_64_sring *sring; };

union blkif_back_rings {
	struct blkif_back_ring        native;
	struct blkif_common_back_ring common;
	struct blkif_x86_32_back_ring x86_32;
	struct blkif_x86_64_back_ring x86_64;
};

enum blkif_protocol {
	BLKIF_PROTOCOL_NATIVE = 1,
	BLKIF_PROTOCOL_X86_32 = 2,
	BLKIF_PROTOCOL_X86_64 = 3,
};

struct xen_vbd {
	/* What the domain refers to this vbd as. */
	blkif_vdev_t		handle;
	/* Non-zero -> read-only */
	unsigned char		readonly;
	/* VDISK_xxx */
	unsigned char		type;
	/* phys device that this vbd maps to. */
	u32			pdevice;
	struct block_device	*bdev;
	/* Cached size parameter. */
	sector_t		size;
	unsigned int		flush_support:1;
	unsigned int		discard_secure:1;
	unsigned int		feature_gnt_persistent:1;
	unsigned int		overflow_max_grants:1;
};

#define XEN_BLKIF_REQS_PER_PAGE		32

struct xen_blkif_ring {
	/* Physical parameters of the comms window. */
	unsigned int		irq;
	union blkif_back_rings	blk_rings;
	void			*blk_ring;
	/* Private fields. */
	spinlock_t		blk_ring_lock;

	wait_queue_head_t	wq;
	atomic_t		inflight;
	bool			active;
	/* One thread per blkif ring. */
	struct task_struct	*xenblkd;
	unsigned int		waiting_reqs;

	/* List of all 'pending_req' available */
	struct list_head	pending_free;
	/* And its spinlock. */
	spinlock_t		pending_free_lock;
	wait_queue_head_t	pending_free_wq;

	/* Tree to store persistent grants. */
	struct rb_root		persistent_gnts;
	unsigned int		persistent_gnt_c;
	atomic_t		persistent_gnt_in_use;
	unsigned long           next_lru;

	/* Statistics. */
	unsigned long		st_print;
	unsigned long long	st_rd_req;
	unsigned long long	st_wr_req;
	unsigned long long	st_oo_req;
	unsigned long long	st_f_req;
	unsigned long long	st_ds_req;
	unsigned long long	st_rd_sect;
	unsigned long long	st_wr_sect;

	/* Used by the kworker that offload work from the persistent purge. */
	struct list_head	persistent_purge_list;
	struct work_struct	persistent_purge_work;

	/* Buffer of free pages to map grant refs. */
	spinlock_t		free_pages_lock;
	int			free_pages_num;
	struct list_head	free_pages;

	struct work_struct	free_work;
	/* Thread shutdown wait queue. */
	wait_queue_head_t	shutdown_wq;
	struct xen_blkif 	*blkif;
};

struct xen_blkif {
	/* Unique identifier for this interface. */
	domid_t			domid;
	unsigned int		handle;
	/* Comms information. */
	enum blkif_protocol	blk_protocol;
	/* The VBD attached to this interface. */
	struct xen_vbd		vbd;
	/* Back pointer to the backend_info. */
	struct backend_info	*be;
	atomic_t		refcnt;
	/* for barrier (drain) requests */
	struct completion	drain_complete;
	atomic_t		drain;

	struct work_struct	free_work;
	unsigned int 		nr_ring_pages;
	/* All rings for this device. */
	struct xen_blkif_ring	*rings;
	unsigned int		nr_rings;
};

struct seg_buf {
	unsigned long offset;
	unsigned int nsec;
};

struct pending_req {
	struct xen_blkif_ring   *ring;
	u64			id;
	int			nr_segs;
	atomic_t		pendcnt;
	unsigned short		operation;
	int			status;
	struct list_head	free_list;
	struct grant_page	*segments[MAX_INDIRECT_SEGMENTS];
	/* Indirect descriptors */
	struct grant_page	*indirect_pages[MAX_INDIRECT_PAGES];
	struct seg_buf		seg[MAX_INDIRECT_SEGMENTS];
	struct bio		*biolist[MAX_INDIRECT_SEGMENTS];
	struct gnttab_unmap_grant_ref unmap[MAX_INDIRECT_SEGMENTS];
	struct page                   *unmap_pages[MAX_INDIRECT_SEGMENTS];
	struct gntab_unmap_queue_data gnttab_unmap_data;
};

static void (*klpe_xen_blkbk_free_caches)(struct xen_blkif_ring *ring);

/* klp-ccp: from drivers/block/xen-blkback/xenbus.c */
struct backend_info {
	struct xenbus_device	*dev;
	struct xen_blkif	*blkif;
	struct xenbus_watch	backend_watch;
	unsigned		major;
	unsigned		minor;
	char			*mode;
};

int klpp_xen_blkif_disconnect(struct xen_blkif *blkif)
{
	struct pending_req *req, *n;
	unsigned int j, r;
	bool busy = false;

	for (r = 0; r < blkif->nr_rings; r++) {
		struct xen_blkif_ring *ring = &blkif->rings[r];
		unsigned int i = 0;

		if (!ring->active)
			continue;

		if (ring->xenblkd) {
			kthread_stop(ring->xenblkd);
			/*
			 * Fix CVE-2020-29569
			 *  +1 line
			 */
			ring->xenblkd = NULL;
			wake_up(&ring->shutdown_wq);
		}

		/* The above kthread_stop() guarantees that at this point we
		 * don't have any discard_io or other_io requests. So, checking
		 * for inflight IO is enough.
		 */
		if (atomic_read(&ring->inflight) > 0) {
			busy = true;
			continue;
		}

		if (ring->irq) {
			unbind_from_irqhandler(ring->irq, ring);
			ring->irq = 0;
		}

		if (ring->blk_rings.common.sring) {
			xenbus_unmap_ring_vfree(blkif->be->dev, ring->blk_ring);
			ring->blk_rings.common.sring = NULL;
		}

		/* Remove all persistent grants and the cache of ballooned pages. */
		(*klpe_xen_blkbk_free_caches)(ring);

		/* Check that there is no request in use */
		list_for_each_entry_safe(req, n, &ring->pending_free, free_list) {
			list_del(&req->free_list);

			for (j = 0; j < MAX_INDIRECT_SEGMENTS; j++)
				kfree(req->segments[j]);

			for (j = 0; j < MAX_INDIRECT_PAGES; j++)
				kfree(req->indirect_pages[j]);

			kfree(req);
			i++;
		}

		BUG_ON(atomic_read(&ring->persistent_gnt_in_use) != 0);
		BUG_ON(!list_empty(&ring->persistent_purge_list));
		BUG_ON(!RB_EMPTY_ROOT(&ring->persistent_gnts));
		BUG_ON(!list_empty(&ring->free_pages));
		BUG_ON(ring->free_pages_num != 0);
		BUG_ON(ring->persistent_gnt_c != 0);
		WARN_ON(i != (XEN_BLKIF_REQS_PER_PAGE * blkif->nr_ring_pages));
		ring->active = false;
	}
	if (busy)
		return -EBUSY;

	blkif->nr_ring_pages = 0;
	/*
	 * blkif->rings was allocated in connect_ring, so we should free it in
	 * here.
	 */
	kfree(blkif->rings);
	blkif->rings = NULL;
	blkif->nr_rings = 0;

	return 0;
}



#include "livepatch_bsc1180008.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "xen_blkback"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "xen_blkbk_free_caches", (void *)&klpe_xen_blkbk_free_caches,
	  "xen_blkback" },
};

static int livepatch_bsc1180008_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1180008_module_nb = {
	.notifier_call = livepatch_bsc1180008_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1180008_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1180008_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1180008_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1180008_module_nb);
}

#endif /* IS_ENABLED(CONFIG_XEN_BLKDEV_BACKEND) */
