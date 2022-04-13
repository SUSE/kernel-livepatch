/*
 * bsc1197344_fuse_file
 *
 * Fix for CVE-2022-1011, bsc#1197344 (fs/fuse/file.c part)
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

/* klp-ccp: from fs/fuse/fuse_i.h */
static void (*klpe_fuse_read_fill)(struct fuse_req *req, struct file *file,
		    loff_t pos, size_t count, int opcode);

static struct fuse_req *(*klpe_fuse_get_req)(struct fuse_conn *fc, unsigned npages);
static struct fuse_req *(*klpe_fuse_get_req_for_background)(struct fuse_conn *fc,
					     unsigned npages);

static void (*klpe_fuse_put_request)(struct fuse_conn *fc, struct fuse_req *req);

static void (*klpe_fuse_request_send)(struct fuse_conn *fc, struct fuse_req *req);

static u64 (*klpe_fuse_lock_owner_id)(struct fuse_conn *fc, fl_owner_t id);

static void (*klpe_fuse_set_nowrite)(struct inode *inode);
static void (*klpe_fuse_release_nowrite)(struct inode *inode);

/* klp-ccp: from fs/fuse/file.c */
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/swap.h>
#include <linux/uio.h>
#include <linux/fs.h>

static bool (*klpe_fuse_range_is_writeback)(struct inode *inode, pgoff_t idx_from,
				   pgoff_t idx_to);

static void klpr_fuse_sync_writes(struct inode *inode)
{
	(*klpe_fuse_set_nowrite)(inode);
	(*klpe_fuse_release_nowrite)(inode);
}

static void fuse_release_user_pages(struct fuse_req *req, bool should_dirty)
{
	unsigned i;

	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (should_dirty)
			set_page_dirty_lock(page);
		put_page(page);
	}
}

static size_t (*klpe_fuse_async_req_send)(struct fuse_conn *fc, struct fuse_req *req,
		size_t num_bytes, struct fuse_io_priv *io);

static size_t klpr_fuse_send_read(struct fuse_req *req, struct fuse_io_priv *io,
			     loff_t pos, size_t count, fl_owner_t owner)
{
	struct file *file = io->file;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;

	(*klpe_fuse_read_fill)(req, file, pos, count, FUSE_READ);
	if (owner != NULL) {
		struct fuse_read_in *inarg = &req->misc.read.in;

		inarg->read_flags |= FUSE_READ_LOCKOWNER;
		inarg->lock_owner = (*klpe_fuse_lock_owner_id)(fc, owner);
	}

	if (io->async)
		return (*klpe_fuse_async_req_send)(fc, req, count, io);

	(*klpe_fuse_request_send)(fc, req);
	return req->out.args[0].size;
}

static size_t (*klpe_fuse_send_write)(struct fuse_req *req, struct fuse_io_priv *io,
			      loff_t pos, size_t count, fl_owner_t owner);

static inline void fuse_page_descs_length_init(struct fuse_req *req,
		unsigned index, unsigned nr_pages)
{
	int i;

	for (i = index; i < index + nr_pages; i++)
		req->page_descs[i].length = PAGE_SIZE -
			req->page_descs[i].offset;
}

static inline unsigned long fuse_get_user_addr(const struct iov_iter *ii)
{
	return (unsigned long)ii->iov->iov_base + ii->iov_offset;
}

static inline size_t fuse_get_frag_size(const struct iov_iter *ii,
					size_t max_size)
{
	return min(iov_iter_single_seg_count(ii), max_size);
}

static int klpp_fuse_get_user_pages(struct fuse_req *req, struct iov_iter *ii,
			       size_t *nbytesp, int write)
{
	size_t nbytes = 0;  /* # bytes already packed in req */
	ssize_t ret = 0;

	/* Special case for kernel I/O: can copy directly into the buffer */
	if (ii->type & ITER_KVEC) {
		unsigned long user_addr = fuse_get_user_addr(ii);
		size_t frag_size = fuse_get_frag_size(ii, *nbytesp);

		if (write)
			req->in.args[1].value = (void *) user_addr;
		else
			req->out.args[0].value = (void *) user_addr;

		iov_iter_advance(ii, frag_size);
		*nbytesp = frag_size;
		return 0;
	}

	while (nbytes < *nbytesp && req->num_pages < req->max_pages) {
		unsigned npages;
		size_t start;
		ret = iov_iter_get_pages(ii, &req->pages[req->num_pages],
					*nbytesp - nbytes,
					req->max_pages - req->num_pages,
					&start);
		if (ret < 0)
			break;

		iov_iter_advance(ii, ret);
		nbytes += ret;

		ret += start;
		npages = (ret + PAGE_SIZE - 1) / PAGE_SIZE;

		req->page_descs[req->num_pages].offset = start;
		fuse_page_descs_length_init(req, req->num_pages, npages);

		req->num_pages += npages;
		req->page_descs[req->num_pages - 1].length -=
			(PAGE_SIZE - ret) & (PAGE_SIZE - 1);
	}

	/*
	 * Fix CVE-2022-1011
	 *  +1 line
	 */
	klpp_fuse_req_set_user_pages(req);

	if (write)
		req->in.argpages = 1;
	else
		req->out.argpages = 1;

	*nbytesp = nbytes;

	return ret < 0 ? ret : 0;
}

static inline int fuse_iter_npages(const struct iov_iter *ii_p)
{
	return iov_iter_npages(ii_p, FUSE_MAX_PAGES_PER_REQ);
}

ssize_t klpp_fuse_direct_io(struct fuse_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags)
{
	int write = flags & FUSE_DIO_WRITE;
	bool should_dirty = !write && iter_is_iovec(iter);
	int cuse = flags & FUSE_DIO_CUSE;
	struct file *file = io->file;
	struct inode *inode = file->f_mapping->host;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	size_t nmax = write ? fc->max_write : fc->max_read;
	loff_t pos = *ppos;
	size_t count = iov_iter_count(iter);
	pgoff_t idx_from = pos >> PAGE_SHIFT;
	pgoff_t idx_to = (pos + count - 1) >> PAGE_SHIFT;
	ssize_t res = 0;
	struct fuse_req *req;
	int err = 0;

	if (io->async)
		req = (*klpe_fuse_get_req_for_background)(fc, fuse_iter_npages(iter));
	else
		req = (*klpe_fuse_get_req)(fc, fuse_iter_npages(iter));
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (!cuse && (*klpe_fuse_range_is_writeback)(inode, idx_from, idx_to)) {
		if (!write)
			inode_lock(inode);
		klpr_fuse_sync_writes(inode);
		if (!write)
			inode_unlock(inode);
	}

	while (count) {
		size_t nres;
		fl_owner_t owner = current->files;
		size_t nbytes = min(count, nmax);
		err = klpp_fuse_get_user_pages(req, iter, &nbytes, write);
		if (err && !nbytes)
			break;

		if (write)
			nres = (*klpe_fuse_send_write)(req, io, pos, nbytes, owner);
		else
			nres = klpr_fuse_send_read(req, io, pos, nbytes, owner);

		if (!io->async)
			fuse_release_user_pages(req, should_dirty);
		if (req->out.h.error) {
			err = req->out.h.error;
			break;
		} else if (nres > nbytes) {
			res = 0;
			err = -EIO;
			break;
		}
		count -= nres;
		res += nres;
		pos += nres;
		if (nres != nbytes)
			break;
		if (count) {
			(*klpe_fuse_put_request)(fc, req);
			if (io->async)
				req = (*klpe_fuse_get_req_for_background)(fc,
					fuse_iter_npages(iter));
			else
				req = (*klpe_fuse_get_req)(fc, fuse_iter_npages(iter));
			if (IS_ERR(req))
				break;
		}
	}
	if (!IS_ERR(req))
		(*klpe_fuse_put_request)(fc, req);
	if (res > 0)
		*ppos = pos;

	return res > 0 ? res : err;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1197344.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "fuse"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fuse_async_req_send", (void *)&klpe_fuse_async_req_send, "fuse" },
	{ "fuse_get_req", (void *)&klpe_fuse_get_req, "fuse" },
	{ "fuse_get_req_for_background",
	  (void *)&klpe_fuse_get_req_for_background, "fuse" },
	{ "fuse_lock_owner_id", (void *)&klpe_fuse_lock_owner_id, "fuse" },
	{ "fuse_put_request", (void *)&klpe_fuse_put_request, "fuse" },
	{ "fuse_range_is_writeback", (void *)&klpe_fuse_range_is_writeback,
	  "fuse" },
	{ "fuse_read_fill", (void *)&klpe_fuse_read_fill, "fuse" },
	{ "fuse_release_nowrite", (void *)&klpe_fuse_release_nowrite, "fuse" },
	{ "fuse_request_send", (void *)&klpe_fuse_request_send, "fuse" },
	{ "fuse_send_write", (void *)&klpe_fuse_send_write, "fuse" },
	{ "fuse_set_nowrite", (void *)&klpe_fuse_set_nowrite, "fuse" },
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

int livepatch_bsc1197344_fuse_file_init(void)
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

void livepatch_bsc1197344_fuse_file_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1197344_module_nb);
}
