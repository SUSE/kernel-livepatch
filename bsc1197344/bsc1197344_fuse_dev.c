/*
 * bsc1197344_fuse_dev
 *
 * Fix for CVE-2022-1011, bsc#1197344 (fs/fuse/dev.c part)
 *
 *  Copyright (c) 2022 SUSE
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

#include "bsc1197344_common.h"

/* klp-ccp: from fs/fuse/dev.c */
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pipe_fs_i.h>
#include <linux/swap.h>
#include <linux/sched.h>

static int (*klpe_lock_request)(struct fuse_req *req);

static int (*klpe_unlock_request)(struct fuse_req *req);

struct fuse_copy_state {
	int write;
	struct fuse_req *req;
	struct iov_iter *iter;
	struct pipe_buffer *pipebufs;
	struct pipe_buffer *currbuf;
	struct pipe_inode_info *pipe;
	unsigned long nr_segs;
	struct page *pg;
	unsigned len;
	unsigned offset;
	unsigned move_pages:1;
};

static void (*klpe_fuse_copy_finish)(struct fuse_copy_state *cs);

static int klpr_fuse_copy_fill(struct fuse_copy_state *cs)
{
	struct page *page;
	int err;

	err = (*klpe_unlock_request)(cs->req);
	if (err)
		return err;

	(*klpe_fuse_copy_finish)(cs);
	if (cs->pipebufs) {
		struct pipe_buffer *buf = cs->pipebufs;

		if (!cs->write) {
			err = pipe_buf_confirm(cs->pipe, buf);
			if (err)
				return err;

			BUG_ON(!cs->nr_segs);
			cs->currbuf = buf;
			cs->pg = buf->page;
			cs->offset = buf->offset;
			cs->len = buf->len;
			cs->pipebufs++;
			cs->nr_segs--;
		} else {
			if (cs->nr_segs == cs->pipe->buffers)
				return -EIO;

			page = alloc_page(GFP_HIGHUSER);
			if (!page)
				return -ENOMEM;

			buf->page = page;
			buf->offset = 0;
			buf->len = 0;

			cs->currbuf = buf;
			cs->pg = page;
			cs->offset = 0;
			cs->len = PAGE_SIZE;
			cs->pipebufs++;
			cs->nr_segs++;
		}
	} else {
		size_t off;
		err = iov_iter_get_pages(cs->iter, &page, PAGE_SIZE, 1, &off);
		if (err < 0)
			return err;
		BUG_ON(!err);
		cs->len = err;
		cs->offset = off;
		cs->pg = page;
		iov_iter_advance(cs->iter, err);
	}

	return (*klpe_lock_request)(cs->req);
}

static int (*klpe_fuse_copy_do)(struct fuse_copy_state *cs, void **val, unsigned *size);

static int fuse_check_page(struct page *page)
{
	if (page_mapcount(page) ||
	    page->mapping != NULL ||
	    page_count(page) != 1 ||
	    (page->flags & PAGE_FLAGS_CHECK_AT_PREP &
	     ~(1 << PG_locked |
	       1 << PG_referenced |
	       1 << PG_uptodate |
	       1 << PG_lru |
	       1 << PG_active |
	       1 << PG_reclaim |
	       1 << PG_waiters))) {
		printk(KERN_WARNING "fuse: trying to steal weird page\n");
		printk(KERN_WARNING "  page=%p index=%li flags=%08lx, count=%i, mapcount=%i, mapping=%p\n", page, page->index, page->flags, page_count(page), page_mapcount(page), page->mapping);
		return 1;
	}
	return 0;
}

static int klpr_fuse_try_move_page(struct fuse_copy_state *cs, struct page **pagep)
{
	int err;
	struct page *oldpage = *pagep;
	struct page *newpage;
	struct pipe_buffer *buf = cs->pipebufs;

	get_page(oldpage);
	err = (*klpe_unlock_request)(cs->req);
	if (err)
		goto out_put_old;

	(*klpe_fuse_copy_finish)(cs);

	err = pipe_buf_confirm(cs->pipe, buf);
	if (err)
		goto out_put_old;

	BUG_ON(!cs->nr_segs);
	cs->currbuf = buf;
	cs->len = buf->len;
	cs->pipebufs++;
	cs->nr_segs--;

	if (cs->len != PAGE_SIZE)
		goto out_fallback;

	if (pipe_buf_steal(cs->pipe, buf) != 0)
		goto out_fallback;

	newpage = buf->page;

	if (!PageUptodate(newpage))
		SetPageUptodate(newpage);

	ClearPageMappedToDisk(newpage);

	if (fuse_check_page(newpage) != 0)
		goto out_fallback_unlock;

	/*
	 * This is a new and locked page, it shouldn't be mapped or
	 * have any special flags on it
	 */
	if (WARN_ON(page_mapped(oldpage)))
		goto out_fallback_unlock;
	if (WARN_ON(page_has_private(oldpage)))
		goto out_fallback_unlock;
	if (WARN_ON(PageDirty(oldpage) || PageWriteback(oldpage)))
		goto out_fallback_unlock;
	if (WARN_ON(PageMlocked(oldpage)))
		goto out_fallback_unlock;

	err = replace_page_cache_page(oldpage, newpage, GFP_KERNEL);
	if (err) {
		unlock_page(newpage);
		goto out_put_old;
	}

	get_page(newpage);

	if (!(buf->flags & PIPE_BUF_FLAG_LRU))
		lru_cache_add_file(newpage);

	/*
	 * Release while we have extra ref on stolen page.  Otherwise
	 * anon_pipe_buf_release() might think the page can be reused.
	 */
	pipe_buf_release(cs->pipe, buf);

	err = 0;
	spin_lock(&cs->req->waitq.lock);
	if (test_bit(FR_ABORTED, &cs->req->flags))
		err = -ENOENT;
	else
		*pagep = newpage;
	spin_unlock(&cs->req->waitq.lock);

	if (err) {
		unlock_page(newpage);
		put_page(newpage);
		goto out_put_old;
	}

	unlock_page(oldpage);
	/* Drop ref for ap->pages[] array */
	put_page(oldpage);
	cs->len = 0;

	err = 0;
out_put_old:
	/* Drop ref obtained in this function */
	put_page(oldpage);
	return err;

out_fallback_unlock:
	unlock_page(newpage);
out_fallback:
	cs->pg = buf->page;
	cs->offset = buf->offset;

	err = (*klpe_lock_request)(cs->req);
	if (!err)
		err = 1;

	goto out_put_old;
}

static int klpr_fuse_ref_page(struct fuse_copy_state *cs, struct page *page,
			 unsigned offset, unsigned count)
{
	struct pipe_buffer *buf;
	int err;

	if (cs->nr_segs == cs->pipe->buffers)
		return -EIO;

	get_page(page);
	err = (*klpe_unlock_request)(cs->req);
	if (err) {
		put_page(page);
		return err;
	}

	(*klpe_fuse_copy_finish)(cs);

	buf = cs->pipebufs;
	buf->page = page;
	buf->offset = offset;
	buf->len = count;

	cs->pipebufs++;
	cs->nr_segs++;
	cs->len = 0;

	return 0;
}

static int klpp_fuse_copy_page(struct fuse_copy_state *cs, struct page **pagep,
			  unsigned offset, unsigned count, int zeroing)
{
	int err;
	struct page *page = *pagep;

	if (page && zeroing && count < PAGE_SIZE)
		clear_highpage(page);

	while (count) {
		if (cs->write && cs->pipebufs && page) {
			/*
			 * Fix CVE-2022-1011
			 *  -1 line, +11 lines
			 */
			/*
			 * Can't control lifetime of pipe buffers, so always
			 * copy user pages.
			 */
			if (klpp_fuse_req_get_user_pages(cs->req)) {
				err = klpr_fuse_copy_fill(cs);
				if (err)
					return err;
			} else {
				return klpr_fuse_ref_page(cs, page, offset, count);
			}
		} else if (!cs->len) {
			if (cs->move_pages && page &&
			    offset == 0 && count == PAGE_SIZE) {
				err = klpr_fuse_try_move_page(cs, pagep);
				if (err <= 0)
					return err;
			} else {
				err = klpr_fuse_copy_fill(cs);
				if (err)
					return err;
			}
		}
		if (page) {
			void *mapaddr = kmap_atomic(page);
			void *buf = mapaddr + offset;
			offset += (*klpe_fuse_copy_do)(cs, &buf, &count);
			kunmap_atomic(mapaddr);
		} else
			offset += (*klpe_fuse_copy_do)(cs, NULL, &count);
	}
	if (page && !cs->write)
		flush_dcache_page(page);
	return 0;
}

static int klpp_fuse_copy_pages(struct fuse_copy_state *cs, unsigned nbytes,
			   int zeroing)
{
	unsigned i;
	struct fuse_req *req = cs->req;

	for (i = 0; i < req->num_pages && (nbytes || zeroing); i++) {
		int err;
		unsigned offset = req->page_descs[i].offset;
		unsigned count = min(nbytes, req->page_descs[i].length);

		err = klpp_fuse_copy_page(cs, &req->pages[i], offset, count,
				     zeroing);
		if (err)
			return err;

		nbytes -= count;
	}
	return 0;
}

static int (*klpe_fuse_copy_one)(struct fuse_copy_state *cs, void *val, unsigned size);

int klpp_fuse_copy_args(struct fuse_copy_state *cs, unsigned numargs,
			  unsigned argpages, struct fuse_arg *args,
			  int zeroing)
{
	int err = 0;
	unsigned i;

	for (i = 0; !err && i < numargs; i++)  {
		struct fuse_arg *arg = &args[i];
		if (i == numargs - 1 && argpages)
			err = klpp_fuse_copy_pages(cs, arg->size, zeroing);
		else
			err = (*klpe_fuse_copy_one)(cs, arg->value, arg->size);
	}
	return err;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1197344.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "fuse"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fuse_copy_do", (void *)&klpe_fuse_copy_do, "fuse" },
	{ "fuse_copy_finish", (void *)&klpe_fuse_copy_finish, "fuse" },
	{ "fuse_copy_one", (void *)&klpe_fuse_copy_one, "fuse" },
	{ "lock_request", (void *)&klpe_lock_request, "fuse" },
	{ "unlock_request", (void *)&klpe_unlock_request, "fuse" },
};

static int livepatch_bsc1197344_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1197344_module_nb = {
	.notifier_call = livepatch_bsc1197344_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1197344_fuse_dev_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1197344_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1197344_fuse_dev_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1197344_module_nb);
}
