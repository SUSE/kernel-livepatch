/*
 * livepatch_bsc1269822
 *
 * Fix for CVE-2026-53133, bsc#1269822
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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


#include "livepatch_bsc1269822.h"


/* klp-ccp: from drivers/infiniband/core/verbs.c */
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/addrconf.h>
#include <linux/security.h>
#include <rdma/ib_verbs.h>

/* klp-ccp: from include/rdma/ib_verbs.h */
bool klpp___rdma_block_iter_next(struct ib_block_iter *biter);

/* klp-ccp: from drivers/infiniband/core/verbs.c */
#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>
#include <rdma/rw.h>
#include <rdma/lag.h>
/* klp-ccp: from drivers/infiniband/core/core_priv.h */
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/cgroup_rdma.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <rdma/ib_verbs.h>
#include <rdma/opa_addr.h>
#include <rdma/ib_mad.h>
#include <rdma/restrack.h>
/* klp-ccp: from drivers/infiniband/core/mad_priv.h */
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/workqueue.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>
#include <rdma/opa_smi.h>
/* klp-ccp: from drivers/infiniband/core/restrack.h */
#include <linux/mutex.h>
/* klp-ccp: from drivers/infiniband/core/verbs.c */
#include <trace/events/rdma_core.h>

bool klpp___rdma_block_iter_next(struct ib_block_iter *biter)
{
	dma_addr_t block_offset;
	dma_addr_t delta;

	if (!biter->__sg_nents || !biter->__sg)
		return false;

	biter->__dma_addr = sg_dma_address(biter->__sg) + biter->__sg_advance;
	block_offset = biter->__dma_addr & (BIT_ULL(biter->__pg_bit) - 1);
	delta = BIT_ULL(biter->__pg_bit) - block_offset;

	while (biter->__sg_nents && biter->__sg &&
	       sg_dma_len(biter->__sg) - biter->__sg_advance <= delta) {
		delta -= sg_dma_len(biter->__sg) - biter->__sg_advance;
		biter->__sg_advance = 0;
		biter->__sg = sg_next(biter->__sg);
		biter->__sg_nents--;
	}
	biter->__sg_advance += delta;

	return true;
}

typeof(klpp___rdma_block_iter_next) klpp___rdma_block_iter_next;


