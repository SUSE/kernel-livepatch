/*
 * livepatch_bsc1182294
 *
 * Fix for CVE-2021-26931, CVE-2021-26930 and CVE-2021-28688, bsc#1182294
 *
 *  Upstream commits:
 *  5a264285ed1c ("xen-blkback: don't "handle" error by BUG()")
 *  871997bc9e42 ("xen-blkback: fix error handling in xen_blkbk_map()")
 *  a846738f8c37 ("xen-blkback: don't leak persistent grants from
 *                 xen_blkbk_map()")
 *
 *  SLE12-SP2 and -SP3 commits:
 *  a89467537d4a6b209a244488b22f83b44d8d40cd
 *  3332ae0680fd07e25efb09efcbea9f6cab633ee7
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  603464d9e61b60751b5ad33d2267e70423fda121
 *  0ed98dcd1f937ba4fa096bd801b65918c0bcf186
 *  55909b8738b3fed7134419b34862fedf4aef0914
 *
 *  SLE15-SP2 commits:
 *  092d4198c9b85634c2142d6c2969b0866863f397
 *  e27d769bd431bb0bbc033bc2a96803f7e9cbb567
 *  f0c74da850d7fe3a9e5d1058a6aba0bc7f51a2db
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

/* klp-ccp: from drivers/block/xen-blkback/blkback.c */
#define pr_fmt(fmt) "xen-blkback: " fmt

#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/freezer.h>
#include <linux/bitmap.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/xen.h>
#include <asm/xen/hypervisor.h>
#include <asm/xen/hypercall.h>
#include <xen/grant_table.h>
/* klp-ccp: from drivers/block/xen-blkback/common.h */
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/io.h>
#include <linux/rbtree.h>
#include <xen/grant_table.h>
#include <xen/page.h>
#include <xen/interface/io/ring.h>
#include <xen/interface/io/blkif.h>
#include <xen/interface/io/protocols.h>

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

struct persistent_gnt {
	struct page *page;
	grant_ref_t gnt;
	grant_handle_t handle;
	unsigned long last_used;
	bool active;
	struct rb_node node;
	struct list_head remove_node;
};

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

struct grant_page {
	struct page 		*page;
	struct persistent_gnt	*persistent_gnt;
	grant_handle_t		handle;
	grant_ref_t		gref;
};

/* klp-ccp: from drivers/block/xen-blkback/blkback.c */
static int (*klpe_xen_blkif_max_pgrants);

#define BLKBACK_INVALID_HANDLE (~0)

static inline int get_free_page(struct xen_blkif_ring *ring, struct page **page)
{
	unsigned long flags;

	spin_lock_irqsave(&ring->free_pages_lock, flags);
	if (list_empty(&ring->free_pages)) {
		BUG_ON(ring->free_pages_num != 0);
		spin_unlock_irqrestore(&ring->free_pages_lock, flags);
		return gnttab_alloc_pages(1, page);
	}
	BUG_ON(ring->free_pages_num == 0);
	page[0] = list_first_entry(&ring->free_pages, struct page, lru);
	list_del(&page[0]->lru);
	ring->free_pages_num--;
	spin_unlock_irqrestore(&ring->free_pages_lock, flags);

	return 0;
}

static inline void put_free_pages(struct xen_blkif_ring *ring, struct page **page,
                                  int num)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&ring->free_pages_lock, flags);
	for (i = 0; i < num; i++)
		list_add(&page[i]->lru, &ring->free_pages);
	ring->free_pages_num += num;
	spin_unlock_irqrestore(&ring->free_pages_lock, flags);
}

#define vaddr(page) ((unsigned long)pfn_to_kaddr(page_to_pfn(page)))

static int klpr_add_persistent_gnt(struct xen_blkif_ring *ring,
			       struct persistent_gnt *persistent_gnt)
{
	struct rb_node **new = NULL, *parent = NULL;
	struct persistent_gnt *this;
	struct xen_blkif *blkif = ring->blkif;

	if (ring->persistent_gnt_c >= (*klpe_xen_blkif_max_pgrants)) {
		if (!blkif->vbd.overflow_max_grants)
			blkif->vbd.overflow_max_grants = 1;
		return -EBUSY;
	}
	/* Figure out where to put new node */
	new = &ring->persistent_gnts.rb_node;
	while (*new) {
		this = container_of(*new, struct persistent_gnt, node);

		parent = *new;
		if (persistent_gnt->gnt < this->gnt)
			new = &((*new)->rb_left);
		else if (persistent_gnt->gnt > this->gnt)
			new = &((*new)->rb_right);
		else {
			pr_alert_ratelimited("trying to add a gref that's already in the tree\n");
			return -EINVAL;
		}
	}

	persistent_gnt->active = true;
	/* Add new node and rebalance tree. */
	rb_link_node(&(persistent_gnt->node), parent, new);
	rb_insert_color(&(persistent_gnt->node), &ring->persistent_gnts);
	ring->persistent_gnt_c++;
	atomic_inc(&ring->persistent_gnt_in_use);
	return 0;
}

static struct persistent_gnt *get_persistent_gnt(struct xen_blkif_ring *ring,
						 grant_ref_t gref)
{
	struct persistent_gnt *data;
	struct rb_node *node = NULL;

	node = ring->persistent_gnts.rb_node;
	while (node) {
		data = container_of(node, struct persistent_gnt, node);

		if (gref < data->gnt)
			node = node->rb_left;
		else if (gref > data->gnt)
			node = node->rb_right;
		else {
			if (data->active) {
				pr_alert_ratelimited("requesting a grant already in use\n");
				return NULL;
			}
			data->active = true;
			atomic_inc(&ring->persistent_gnt_in_use);
			return data;
		}
	}
	return NULL;
}

int klpp_xen_blkbk_map(struct xen_blkif_ring *ring,
			 struct grant_page *pages[],
			 int num, bool ro)
{
	struct gnttab_map_grant_ref map[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	struct page *pages_to_gnt[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	struct persistent_gnt *persistent_gnt = NULL;
	phys_addr_t addr = 0;
	int i, seg_idx, new_map_idx;
	int segs_to_map = 0;
	int ret = 0;
	int last_map = 0, map_until = 0;
	int use_persistent_gnts;
	struct xen_blkif *blkif = ring->blkif;

	use_persistent_gnts = (blkif->vbd.feature_gnt_persistent);

	/*
	 * Fill out preq.nr_sects with proper amount of sectors, and setup
	 * assign map[..] with the PFN of the page in our domain with the
	 * corresponding grant reference for each page.
	 */
again:
	for (i = map_until; i < num; i++) {
		uint32_t flags;

		if (use_persistent_gnts) {
			persistent_gnt = get_persistent_gnt(
				ring,
				pages[i]->gref);
		}

		if (persistent_gnt) {
			/*
			 * We are using persistent grants and
			 * the grant is already mapped
			 */
			pages[i]->page = persistent_gnt->page;
			pages[i]->persistent_gnt = persistent_gnt;
		} else {
			/*
			 * Fix CVE-2021-26930
			 *  -2 lines, +5 lines
			 */
			if (get_free_page(ring, &pages[i]->page)) {
				put_free_pages(ring, pages_to_gnt, segs_to_map);
				ret = -ENOMEM;
				goto out;
			}
			addr = vaddr(pages[i]->page);
			pages_to_gnt[segs_to_map] = pages[i]->page;
			pages[i]->persistent_gnt = NULL;
			flags = GNTMAP_host_map;
			if (!use_persistent_gnts && ro)
				flags |= GNTMAP_readonly;
			gnttab_set_map_op(&map[segs_to_map++], addr,
					  flags, pages[i]->gref,
					  blkif->domid);
		}
		map_until = i + 1;
		if (segs_to_map == BLKIF_MAX_SEGMENTS_PER_REQUEST)
			break;
	}

	if (segs_to_map) {
		ret = gnttab_map_refs(map, NULL, pages_to_gnt, segs_to_map);
		/*
		 * Fix CVE-2021-26931
		 *  -1 line
		 */
	}

	/*
	 * Now swizzle the MFN in our domain with the MFN from the other domain
	 * so that when we access vaddr(pending_req,i) it has the contents of
	 * the page from the other domain.
	 */
	for (seg_idx = last_map, new_map_idx = 0; seg_idx < map_until; seg_idx++) {
		if (!pages[seg_idx]->persistent_gnt) {
			/* This is a newly mapped grant */
			BUG_ON(new_map_idx >= segs_to_map);
			if (unlikely(map[new_map_idx].status != 0)) {
				pr_debug("invalid buffer -- could not remap it\n");
				put_free_pages(ring, &pages[seg_idx]->page, 1);
				pages[seg_idx]->handle = BLKBACK_INVALID_HANDLE;
				/*
				 * Fix CVE-2021-26931
				 *  -1 line, +1 line
				 */
				ret |= !ret;
				goto next;
			}
			pages[seg_idx]->handle = map[new_map_idx].handle;
		} else {
			continue;
		}
		if (use_persistent_gnts &&
		    ring->persistent_gnt_c < (*klpe_xen_blkif_max_pgrants)) {
			/*
			 * We are using persistent grants, the grant is
			 * not mapped but we might have room for it.
			 */
			persistent_gnt = kmalloc(sizeof(struct persistent_gnt),
				                 GFP_KERNEL);
			if (!persistent_gnt) {
				/*
				 * If we don't have enough memory to
				 * allocate the persistent_gnt struct
				 * map this grant non-persistenly
				 */
				goto next;
			}
			persistent_gnt->gnt = map[new_map_idx].ref;
			persistent_gnt->handle = map[new_map_idx].handle;
			persistent_gnt->page = pages[seg_idx]->page;
			if (klpr_add_persistent_gnt(ring,
			                       persistent_gnt)) {
				kfree(persistent_gnt);
				persistent_gnt = NULL;
				goto next;
			}
			pages[seg_idx]->persistent_gnt = persistent_gnt;
			pr_debug("grant %u added to the tree of persistent grants, using %u/%u\n",
				 persistent_gnt->gnt, ring->persistent_gnt_c,
				 (*klpe_xen_blkif_max_pgrants));
			goto next;
		}
		if (use_persistent_gnts && !blkif->vbd.overflow_max_grants) {
			blkif->vbd.overflow_max_grants = 1;
			pr_debug("domain %u, device %#x is using maximum number of persistent grants\n",
			         blkif->domid, blkif->vbd.handle);
		}
		/*
		 * We could not map this grant persistently, so use it as
		 * a non-persistent grant.
		 */
next:
		new_map_idx++;
	}
	segs_to_map = 0;
	last_map = map_until;
	/*
	 * Fix CVE-2021-26930
	 *  -1 line, +1 line
	 */
	if (!ret && map_until != num)
		goto again;

	/*
	 * Fix CVE-2021-26930
	 *  -8 lines, +9 lines
	 */
out:
	for (i = last_map; i < num; i++) {
		/* Don't zap current batch's valid persistent grants. */
		if(i >= map_until)
			pages[i]->persistent_gnt = NULL;
		pages[i]->handle = BLKBACK_INVALID_HANDLE;
	}

	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1182294.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "xen_blkback"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "xen_blkif_max_pgrants", (void *)&klpe_xen_blkif_max_pgrants,
	  "xen_blkback" },
};

static int livepatch_bsc1182294_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1182294_module_nb = {
	.notifier_call = livepatch_bsc1182294_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1182294_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1182294_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1182294_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1182294_module_nb);
}

#endif /* IS_ENABLED(CONFIG_XEN_BLKDEV_BACKEND) */
