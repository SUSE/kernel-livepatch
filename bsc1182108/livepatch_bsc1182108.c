/*
 * livepatch_bsc1182108
 *
 * Fix for bsc#1182108
 *
 *  Upstream commits:
 *  06c9fdf3b9f1 ("NFS: On fatal writeback errors, we need to call
 *                 nfs_inode_remove_request()")
 *  b8946d7bfb94 ("NFS: Revalidate the file mapping on all fatal writeback
 *                 errors")
 *
 *  SLE12-SP2 and -SP3 commits:
 *  not affected
 *
 *  SLE15 commits:
 *  not affected
 *
 *  SLE12-SP4 commits:
 *  a0648a0e42ab8c2787f9ded9023a367fd2e9d5fe
 *  2b920c40e6e5d7bf81b75e5da890f60034155e92
 *
 *  SLE12-SP5 and SLE15-SP1 commits:
 *  eca201ff6c49d6d607a22f854c7cc818e3e11c7d
 *  e8e4449b3eed5ce844501e29090753311d68bf96
 *
 *  SLE15-SP2 commits:
 *  not affected
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

#if !IS_MODULE(CONFIG_NFS_FS)
#error "Live patch supports only CONFIG_NFS_FS=m"
#endif

/* klp-ccp: from fs/nfs/write.c */
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/swap.h>
#include <linux/sunrpc/clnt.h>
#include <linux/nfs_fs.h>

/* klp-ccp: from include/linux/nfs_fs.h */
static int  (*klpe_nfs_congestion_kb);

/* klp-ccp: from fs/nfs/write.c */
#include <linux/nfs_page.h>

/* klp-ccp: from include/linux/nfs_page.h */
static	void (*klpe_nfs_release_request)(struct nfs_page *);

static	int (*klpe_nfs_pageio_add_request)(struct nfs_pageio_descriptor *,
				   struct nfs_page *);

static	void (*klpe_nfs_pageio_cond_complete)(struct nfs_pageio_descriptor *, pgoff_t);

static	void (*klpe_nfs_unlock_request)(struct nfs_page *req);

/* klp-ccp: from fs/nfs/write.c */
#include <linux/backing-dev.h>
#include <linux/export.h>
#include <linux/wait.h>
#include <linux/uaccess.h>

/* klp-ccp: from fs/nfs/nfs4_fs.h */
#include <linux/seqlock.h>

/* klp-ccp: from fs/nfs/internal.h */
#include <linux/security.h>
#include <linux/nfs_page.h>
#include <linux/wait_bit.h>

static inline bool nfs_error_is_fatal(int err)
{
	switch (err) {
	case -ERESTARTSYS:
	case -EACCES:
	case -EDQUOT:
	case -EFBIG:
	case -EIO:
	case -ENOSPC:
	case -EROFS:
	case -ESTALE:
	case -E2BIG:
		return true;
	default:
		return false;
	}
}

/* klp-ccp: from fs/nfs/iostat.h */
#include <linux/percpu.h>
#include <linux/cache.h>
#include <linux/nfs_iostat.h>

struct nfs_iostats {
	unsigned long long	bytes[__NFSIOS_BYTESMAX];
#ifdef CONFIG_NFS_FSCACHE
	unsigned long long	fscache[__NFSIOS_FSCACHEMAX];
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	unsigned long		events[__NFSIOS_COUNTSMAX];
} ____cacheline_aligned;

static inline void nfs_add_server_stats(const struct nfs_server *server,
					enum nfs_stat_bytecounters stat,
					long addend)
{
	this_cpu_add(server->io_stats->bytes[stat], addend);
}

static inline void nfs_add_stats(const struct inode *inode,
				 enum nfs_stat_bytecounters stat,
				 long addend)
{
	nfs_add_server_stats(NFS_SERVER(inode), stat, addend);
}

/* klp-ccp: from fs/nfs/fscache.h */
#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>
/* klp-ccp: from fs/nfs/pnfs.h */
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
#include <linux/workqueue.h>

/* klp-ccp: from fs/nfs/write.c */
static void (*klpe_nfs_redirty_request)(struct nfs_page *req);

static void nfs_context_set_write_error(struct nfs_open_context *ctx, int error)
{
	ctx->error = error;
	smp_wmb();
	set_bit(NFS_CONTEXT_ERROR_WRITE, &ctx->flags);
}

static void (*klpe_nfs_set_pageerror)(struct address_space *mapping);

static void klpr_nfs_set_page_writeback(struct page *page)
{
	struct inode *inode = page_file_mapping(page)->host;
	struct nfs_server *nfss = NFS_SERVER(inode);
	int ret = test_set_page_writeback(page);

	WARN_ON_ONCE(ret != 0);

	if (atomic_long_inc_return(&nfss->writeback) >
			((*klpe_nfs_congestion_kb) >> (12 -10)))
		set_bdi_congested(inode_to_bdi(inode), BLK_RW_ASYNC);
}

static void (*klpe_nfs_end_page_writeback)(struct nfs_page *req);

static struct nfs_page *
(*klpe_nfs_lock_and_join_requests)(struct page *page, bool nonblock);

static void (*klpe_nfs_inode_remove_request)(struct nfs_page *req);

static void klpp_nfs_write_error_remove_page(struct nfs_page *req)
{
	(*klpe_nfs_unlock_request)(req);
	SetPageError(req->wb_page);
	/*
	 * Fix bsc#1182108
	 *  +2 lines
	 */
	(*klpe_nfs_set_pageerror)(page_file_mapping(req->wb_page));
	(*klpe_nfs_inode_remove_request)(req);
	(*klpe_nfs_end_page_writeback)(req);
	(*klpe_nfs_release_request)(req);
}

static bool
(*klpe_nfs_error_is_fatal_on_server)(int err);

static int klpp_nfs_page_async_flush(struct nfs_pageio_descriptor *pgio,
				struct page *page, bool nonblock)
{
	struct nfs_page *req;
	int ret = 0;

	req = (*klpe_nfs_lock_and_join_requests)(page, nonblock);
	if (!req)
		goto out;
	ret = PTR_ERR(req);
	if (IS_ERR(req))
		goto out;

	klpr_nfs_set_page_writeback(page);
	WARN_ON_ONCE(test_bit(PG_CLEAN, &req->wb_flags));

	ret = req->wb_context->error;
	/* If there is a fatal error that covers this write, just exit */
	if ((*klpe_nfs_error_is_fatal_on_server)(ret))
		goto out_launder;

	ret = 0;
	if (!(*klpe_nfs_pageio_add_request)(pgio, req)) {
		ret = pgio->pg_error;
		/*
		 * Remove the problematic req upon fatal errors on the server
		 */
		if (nfs_error_is_fatal(ret)) {
			nfs_context_set_write_error(req->wb_context, ret);
			if ((*klpe_nfs_error_is_fatal_on_server)(ret))
				goto out_launder;
		} else
			ret = -EAGAIN;
		(*klpe_nfs_redirty_request)(req);
	} else
		nfs_add_stats(page_file_mapping(page)->host,
				NFSIOS_WRITEPAGES, 1);
out:
	return ret;
out_launder:
	klpp_nfs_write_error_remove_page(req);
	return 0;
}

int klpp_nfs_do_writepage(struct page *page, struct writeback_control *wbc,
			    struct nfs_pageio_descriptor *pgio)
{
	int ret;

	(*klpe_nfs_pageio_cond_complete)(pgio, page_index(page));
	ret = klpp_nfs_page_async_flush(pgio, page, wbc->sync_mode == WB_SYNC_NONE);
	if (ret == -EAGAIN) {
		redirty_page_for_writepage(wbc, page);
		ret = 0;
	}
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1182108.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nfs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfs_congestion_kb", (void *)&klpe_nfs_congestion_kb, "nfs" },
	{ "nfs_release_request", (void *)&klpe_nfs_release_request, "nfs" },
	{ "nfs_pageio_add_request", (void *)&klpe_nfs_pageio_add_request,
	  "nfs" },
	{ "nfs_pageio_cond_complete", (void *)&klpe_nfs_pageio_cond_complete,
	  "nfs" },
	{ "nfs_unlock_request", (void *)&klpe_nfs_unlock_request, "nfs" },
	{ "nfs_lock_and_join_requests",
	  (void *)&klpe_nfs_lock_and_join_requests, "nfs" },
	{ "nfs_redirty_request", (void *)&klpe_nfs_redirty_request, "nfs" },
	{ "nfs_end_page_writeback", (void *)&klpe_nfs_end_page_writeback,
	  "nfs" },
	{ "nfs_error_is_fatal_on_server",
	  (void *)&klpe_nfs_error_is_fatal_on_server, "nfs" },
	{ "nfs_set_pageerror", (void *)&klpe_nfs_set_pageerror, "nfs" },
	{ "nfs_inode_remove_request", (void *)&klpe_nfs_inode_remove_request,
	  "nfs" },
};

static int livepatch_bsc1182108_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1182108_module_nb = {
	.notifier_call = livepatch_bsc1182108_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1182108_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1182108_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1182108_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1182108_module_nb);
}
