/*
 * bsc1184952_fuse_file
 *
 * Fix for CVE-2020-36322, bsc#1184952 (fs/fuse/file.c part)
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

#include "bsc1184952_common.h"

/* klp-ccp: from fs/fuse/fuse_i.h */
static void (*klpe_fuse_read_fill)(struct fuse_req *req, struct file *file,
		    loff_t pos, size_t count, int opcode);

int klpp_fuse_open_common(struct inode *inode, struct file *file, bool isdir);

static void (*klpe_fuse_finish_open)(struct inode *inode, struct file *file);

int klpp_fuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int isdir);

static struct fuse_req *(*klpe_fuse_get_req)(struct fuse_conn *fc, unsigned npages);
static struct fuse_req *(*klpe_fuse_get_req_for_background)(struct fuse_conn *fc,
					     unsigned npages);

static struct fuse_req *(*klpe_fuse_get_req_nofail_nopages)(struct fuse_conn *fc,
					     struct file *file);

static void (*klpe_fuse_put_request)(struct fuse_conn *fc, struct fuse_req *req);

static void (*klpe_fuse_request_send)(struct fuse_conn *fc, struct fuse_req *req);

static ssize_t (*klpe_fuse_simple_request)(struct fuse_conn *fc, struct fuse_args *args);

static void (*klpe_fuse_request_send_background)(struct fuse_conn *fc, struct fuse_req *req);

static void (*klpe_fuse_invalidate_attr)(struct inode *inode);

static void (*klpe_fuse_invalidate_atime)(struct inode *inode);

static int (*klpe_fuse_allow_current_process)(struct fuse_conn *fc);

static u64 (*klpe_fuse_lock_owner_id)(struct fuse_conn *fc, fl_owner_t id);

static int (*klpe_fuse_update_attributes)(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed);

static void (*klpe_fuse_set_nowrite)(struct inode *inode);
static void (*klpe_fuse_release_nowrite)(struct inode *inode);

static u64 (*klpe_fuse_get_attr_version)(struct fuse_conn *fc);

static int (*klpe_fuse_do_open)(struct fuse_conn *fc, u64 nodeid, struct file *file,
		 bool isdir);

static ssize_t (*klpe_fuse_direct_io)(struct fuse_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags);
static long (*klpe_fuse_do_ioctl)(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags);
long klpp_fuse_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags);

static bool (*klpe_fuse_write_update_size)(struct inode *inode, loff_t pos);

/* klp-ccp: from fs/fuse/file.c */
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/swap.h>
#include <linux/uio.h>

static struct fuse_file *fuse_file_get(struct fuse_file *ff)
{
	refcount_inc(&ff->count);
	return ff;
}

static void (*klpe_fuse_release_end)(struct fuse_conn *fc, struct fuse_req *req);

static void klpr_fuse_file_put(struct fuse_file *ff, bool sync, bool isdir)
{
	if (refcount_dec_and_test(&ff->count)) {
		struct fuse_req *req = ff->reserved_req;

		if (ff->fc->no_open && !isdir) {
			/*
			 * Drop the release request when client does not
			 * implement 'open'
			 */
			__clear_bit(FR_BACKGROUND, &req->flags);
			iput(req->misc.release.inode);
			(*klpe_fuse_put_request)(ff->fc, req);
		} else if (sync) {
			__set_bit(FR_FORCE, &req->flags);
			__clear_bit(FR_BACKGROUND, &req->flags);
			(*klpe_fuse_request_send)(ff->fc, req);
			iput(req->misc.release.inode);
			(*klpe_fuse_put_request)(ff->fc, req);
		} else {
			req->end = (*klpe_fuse_release_end);
			__set_bit(FR_BACKGROUND, &req->flags);
			(*klpe_fuse_request_send_background)(ff->fc, req);
		}
		kfree(ff);
	}
}

int klpp_fuse_open_common(struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err;
	bool lock_inode = (file->f_flags & O_TRUNC) &&
			  fc->atomic_o_trunc &&
			  fc->writeback_cache;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	err = generic_file_open(inode, file);
	if (err)
		return err;

	if (lock_inode)
		inode_lock(inode);

	err = (*klpe_fuse_do_open)(fc, get_node_id(inode), file, isdir);

	if (!err)
		(*klpe_fuse_finish_open)(inode, file);

	if (lock_inode)
		inode_unlock(inode);

	return err;
}

static int (*klpe_fuse_wait_on_page_writeback)(struct inode *inode, pgoff_t index);

static void klpr_fuse_sync_writes(struct inode *inode)
{
	(*klpe_fuse_set_nowrite)(inode);
	(*klpe_fuse_release_nowrite)(inode);
}

int klpp_fuse_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_flush_in inarg;
	int err;

	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	if (fc->no_flush)
		return 0;

	err = write_inode_now(inode, 1);
	if (err)
		return err;

	inode_lock(inode);
	klpr_fuse_sync_writes(inode);
	inode_unlock(inode);

	err = filemap_check_errors(file->f_mapping);
	if (err)
		return err;

	req = (*klpe_fuse_get_req_nofail_nopages)(fc, file);
	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.lock_owner = (*klpe_fuse_lock_owner_id)(fc, id);
	req->in.h.opcode = FUSE_FLUSH;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	__set_bit(FR_FORCE, &req->flags);
	(*klpe_fuse_request_send)(fc, req);
	err = req->out.h.error;
	(*klpe_fuse_put_request)(fc, req);
	if (err == -ENOSYS) {
		fc->no_flush = 1;
		err = 0;
	}
	return err;
}

int klpp_fuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int isdir)
{
	struct inode *inode = file->f_mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	FUSE_ARGS(args);
	struct fuse_fsync_in inarg;
	int err;

	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	inode_lock(inode);

	/*
	 * Start writeback against all dirty pages of the inode, then
	 * wait for all outstanding writes, before sending the FSYNC
	 * request.
	 */
	err = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (err)
		goto out;

	klpr_fuse_sync_writes(inode);

	/*
	 * Due to implementation of fuse writeback
	 * filemap_write_and_wait_range() does not catch errors.
	 * We have to do this directly after fuse_sync_writes()
	 */
	err = filemap_check_errors(file->f_mapping);
	if (err)
		goto out;

	err = sync_inode_metadata(inode, 1);
	if (err)
		goto out;

	if ((!isdir && fc->no_fsync) || (isdir && fc->no_fsyncdir))
		goto out;

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.fsync_flags = datasync ? 1 : 0;
	args.in.h.opcode = isdir ? FUSE_FSYNCDIR : FUSE_FSYNC;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	err = (*klpe_fuse_simple_request)(fc, &args);
	if (err == -ENOSYS) {
		if (isdir)
			fc->no_fsyncdir = 1;
		else
			fc->no_fsync = 1;
		err = 0;
	}
out:
	inode_unlock(inode);
	return err;
}

static int (*klpe_fuse_do_readpage)(struct file *file, struct page *page);

int klpp_fuse_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	int err;

	err = -EIO;
	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		goto out;

	err = (*klpe_fuse_do_readpage)(file, page);
	(*klpe_fuse_invalidate_atime)(inode);
 out:
	unlock_page(page);
	return err;
}

static void (*klpe_fuse_readpages_end)(struct fuse_conn *fc, struct fuse_req *req);

static void klpr_fuse_send_readpages(struct fuse_req *req, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	loff_t pos = page_offset(req->pages[0]);
	size_t count = req->num_pages << PAGE_SHIFT;

	req->out.argpages = 1;
	req->out.page_zeroing = 1;
	req->out.page_replace = 1;
	(*klpe_fuse_read_fill)(req, file, pos, count, FUSE_READ);
	req->misc.read.attr_ver = (*klpe_fuse_get_attr_version)(fc);
	if (fc->async_read) {
		req->ff = fuse_file_get(ff);
		req->end = (*klpe_fuse_readpages_end);
		(*klpe_fuse_request_send_background)(fc, req);
	} else {
		(*klpe_fuse_request_send)(fc, req);
		(*klpe_fuse_readpages_end)(fc, req);
		(*klpe_fuse_put_request)(fc, req);
	}
}

struct fuse_fill_data {
	struct fuse_req *req;
	struct file *file;
	struct inode *inode;
	unsigned nr_pages;
};

static int (*klpe_fuse_readpages_fill)(void *_data, struct page *page);

int klpp_fuse_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_fill_data data;
	int err;
	int nr_alloc = min_t(unsigned, nr_pages, FUSE_MAX_PAGES_PER_REQ);

	err = -EIO;
	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		goto out;

	data.file = file;
	data.inode = inode;
	if (fc->async_read)
		data.req = (*klpe_fuse_get_req_for_background)(fc, nr_alloc);
	else
		data.req = (*klpe_fuse_get_req)(fc, nr_alloc);
	data.nr_pages = nr_pages;
	err = PTR_ERR(data.req);
	if (IS_ERR(data.req))
		goto out;

	err = read_cache_pages(mapping, pages, (*klpe_fuse_readpages_fill), &data);
	if (!err) {
		if (data.req->num_pages)
			klpr_fuse_send_readpages(data.req, file);
		else
			(*klpe_fuse_put_request)(fc, data.req);
	}
out:
	return err;
}

static size_t (*klpe_fuse_send_write)(struct fuse_req *req, struct fuse_io_priv *io,
			      loff_t pos, size_t count, fl_owner_t owner);

static size_t klpr_fuse_send_write_pages(struct fuse_req *req, struct file *file,
				    struct inode *inode, loff_t pos,
				    size_t count)
{
	size_t res;
	unsigned offset;
	unsigned i;
	struct fuse_io_priv io = FUSE_IO_PRIV_SYNC(file);

	for (i = 0; i < req->num_pages; i++)
		(*klpe_fuse_wait_on_page_writeback)(inode, req->pages[i]->index);

	res = (*klpe_fuse_send_write)(req, &io, pos, count, NULL);

	offset = req->page_descs[0].offset;
	count = res;
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];

		if (!req->out.h.error && !offset && count >= PAGE_SIZE)
			SetPageUptodate(page);

		if (count > PAGE_SIZE - offset)
			count -= PAGE_SIZE - offset;
		else
			count = 0;
		offset = 0;

		unlock_page(page);
		put_page(page);
	}

	return res;
}

static ssize_t fuse_fill_write_pages(struct fuse_req *req,
			       struct address_space *mapping,
			       struct iov_iter *ii, loff_t pos)
{
	struct fuse_conn *fc = get_fuse_conn(mapping->host);
	unsigned offset = pos & (PAGE_SIZE - 1);
	size_t count = 0;
	int err;

	req->in.argpages = 1;
	req->page_descs[0].offset = offset;

	do {
		size_t tmp;
		struct page *page;
		pgoff_t index = pos >> PAGE_SHIFT;
		size_t bytes = min_t(size_t, PAGE_SIZE - offset,
				     iov_iter_count(ii));

		bytes = min_t(size_t, bytes, fc->max_write - count);

 again:
		err = -EFAULT;
		if (iov_iter_fault_in_readable(ii, bytes))
			break;

		err = -ENOMEM;
		page = grab_cache_page_write_begin(mapping, index, 0);
		if (!page)
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		tmp = iov_iter_copy_from_user_atomic(page, ii, offset, bytes);
		flush_dcache_page(page);

		iov_iter_advance(ii, tmp);
		if (!tmp) {
			unlock_page(page);
			put_page(page);
			bytes = min(bytes, iov_iter_single_seg_count(ii));
			goto again;
		}

		err = 0;
		req->pages[req->num_pages] = page;
		req->page_descs[req->num_pages].length = tmp;
		req->num_pages++;

		count += tmp;
		pos += tmp;
		offset += tmp;
		if (offset == PAGE_SIZE)
			offset = 0;

		if (!fc->big_writes)
			break;
	} while (iov_iter_count(ii) && count < fc->max_write &&
		 req->num_pages < req->max_pages && offset == 0);

	return count > 0 ? count : err;
}

static inline unsigned fuse_wr_pages(loff_t pos, size_t len)
{
	return min_t(unsigned,
		     ((pos + len - 1) >> PAGE_SHIFT) -
		     (pos >> PAGE_SHIFT) + 1,
		     FUSE_MAX_PAGES_PER_REQ);
}

ssize_t klpp_fuse_perform_write(struct file *file,
				  struct address_space *mapping,
				  struct iov_iter *ii, loff_t pos)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err = 0;
	ssize_t res = 0;

	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	if (inode->i_size < pos + iov_iter_count(ii))
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	do {
		struct fuse_req *req;
		ssize_t count;
		unsigned nr_pages = fuse_wr_pages(pos, iov_iter_count(ii));

		req = (*klpe_fuse_get_req)(fc, nr_pages);
		if (IS_ERR(req)) {
			err = PTR_ERR(req);
			break;
		}

		count = fuse_fill_write_pages(req, mapping, ii, pos);
		if (count <= 0) {
			err = count;
		} else {
			size_t num_written;

			num_written = klpr_fuse_send_write_pages(req, file, inode,
							    pos, count);
			err = req->out.h.error;
			if (!err) {
				res += num_written;
				pos += num_written;

				/* break out of the loop on short write */
				if (num_written != count)
					err = -EIO;
			}
		}
		(*klpe_fuse_put_request)(fc, req);
	} while (!err && iov_iter_count(ii));

	if (res > 0)
		(*klpe_fuse_write_update_size)(inode, pos);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	(*klpe_fuse_invalidate_attr)(inode);

	return res > 0 ? res : err;
}

ssize_t klpp_fuse_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	ssize_t written = 0;
	ssize_t written_buffered = 0;
	struct inode *inode = mapping->host;
	ssize_t err;
	loff_t endbyte = 0;

	/*
	 * Fix CVE-2020-36322
	 *  +3 lines
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	if (get_fuse_conn(inode)->writeback_cache) {
		/* Update size (EOF optimization) and mode (SUID clearing) */
		err = (*klpe_fuse_update_attributes)(mapping->host, NULL, file, NULL);
		if (err)
			return err;

		return generic_file_write_iter(iocb, from);
	}

	inode_lock(inode);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);

	err = generic_write_checks(iocb, from);
	if (err <= 0)
		goto out;

	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		loff_t pos = iocb->ki_pos;
		written = generic_file_direct_write(iocb, from);
		if (written < 0 || !iov_iter_count(from))
			goto out;

		pos += written;

		written_buffered = klpp_fuse_perform_write(file, mapping, from, pos);
		if (written_buffered < 0) {
			err = written_buffered;
			goto out;
		}
		endbyte = pos + written_buffered - 1;

		err = filemap_write_and_wait_range(file->f_mapping, pos,
						   endbyte);
		if (err)
			goto out;

		invalidate_mapping_pages(file->f_mapping,
					 pos >> PAGE_SHIFT,
					 endbyte >> PAGE_SHIFT);

		written += written_buffered;
		iocb->ki_pos = pos + written_buffered;
	} else {
		written = klpp_fuse_perform_write(file, mapping, from, iocb->ki_pos);
		if (written >= 0)
			iocb->ki_pos += written;
	}
out:
	current->backing_dev_info = NULL;
	inode_unlock(inode);

	return written ? written : err;
}

ssize_t klpp___fuse_direct_read(struct fuse_io_priv *io,
				  struct iov_iter *iter,
				  loff_t *ppos)
{
	ssize_t res;
	struct file *file = io->file;
	struct inode *inode = file_inode(file);

	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	res = (*klpe_fuse_direct_io)(io, iter, ppos, 0);

	(*klpe_fuse_invalidate_attr)(inode);

	return res;
}

ssize_t klpp_fuse_direct_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct fuse_io_priv io = FUSE_IO_PRIV_SYNC(file);
	ssize_t res;

	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	/* Don't allow parallel writes to the same file */
	inode_lock(inode);
	res = generic_write_checks(iocb, from);
	if (res > 0)
		res = (*klpe_fuse_direct_io)(&io, from, &iocb->ki_pos, FUSE_DIO_WRITE);
	(*klpe_fuse_invalidate_attr)(inode);
	if (res > 0)
		(*klpe_fuse_write_update_size)(inode, iocb->ki_pos);
	inode_unlock(inode);

	return res;
}

struct fuse_fill_wb_data {
	struct fuse_req *req;
	struct fuse_file *ff;
	struct inode *inode;
	struct page **orig_pages;
};

static void (*klpe_fuse_writepages_send)(struct fuse_fill_wb_data *data);

static int (*klpe_fuse_writepages_fill)(struct page *page,
		struct writeback_control *wbc, void *_data);

int klpp_fuse_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct fuse_fill_wb_data data;
	int err;

	err = -EIO;
	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		goto out;

	data.inode = inode;
	data.req = NULL;
	data.ff = NULL;

	err = -ENOMEM;
	data.orig_pages = kcalloc(FUSE_MAX_PAGES_PER_REQ,
				  sizeof(struct page *),
				  GFP_NOFS);
	if (!data.orig_pages)
		goto out;

	err = write_cache_pages(mapping, wbc, (*klpe_fuse_writepages_fill), &data);
	if (data.req) {
		/* Ignore errors if we can write at least one page */
		BUG_ON(!data.req->num_pages);
		(*klpe_fuse_writepages_send)(&data);
		err = 0;
	}
	if (data.ff)
		klpr_fuse_file_put(data.ff, false, false);

	kfree(data.orig_pages);
out:
	return err;
}

long klpp_fuse_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (!(*klpe_fuse_allow_current_process)(fc))
		return -EACCES;

	/*
	 * Fix CVE-2020-36322
	 *  -1 line, +1 line
	 */
	if (klpp_fuse_is_bad(inode))
		return -EIO;

	return (*klpe_fuse_do_ioctl)(file, cmd, arg, flags);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1184952.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "fuse"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fuse_read_fill", (void *)&klpe_fuse_read_fill, "fuse" },
	{ "fuse_finish_open", (void *)&klpe_fuse_finish_open, "fuse" },
	{ "fuse_get_req", (void *)&klpe_fuse_get_req, "fuse" },
	{ "fuse_get_req_for_background",
	  (void *)&klpe_fuse_get_req_for_background, "fuse" },
	{ "fuse_get_req_nofail_nopages",
	  (void *)&klpe_fuse_get_req_nofail_nopages, "fuse" },
	{ "fuse_put_request", (void *)&klpe_fuse_put_request, "fuse" },
	{ "fuse_request_send", (void *)&klpe_fuse_request_send, "fuse" },
	{ "fuse_simple_request", (void *)&klpe_fuse_simple_request, "fuse" },
	{ "fuse_request_send_background",
	  (void *)&klpe_fuse_request_send_background, "fuse" },
	{ "fuse_invalidate_attr", (void *)&klpe_fuse_invalidate_attr, "fuse" },
	{ "fuse_invalidate_atime", (void *)&klpe_fuse_invalidate_atime,
	  "fuse" },
	{ "fuse_allow_current_process",
	  (void *)&klpe_fuse_allow_current_process, "fuse" },
	{ "fuse_lock_owner_id", (void *)&klpe_fuse_lock_owner_id, "fuse" },
	{ "fuse_update_attributes", (void *)&klpe_fuse_update_attributes,
	  "fuse" },
	{ "fuse_set_nowrite", (void *)&klpe_fuse_set_nowrite, "fuse" },
	{ "fuse_release_nowrite", (void *)&klpe_fuse_release_nowrite, "fuse" },
	{ "fuse_get_attr_version", (void *)&klpe_fuse_get_attr_version,
	  "fuse" },
	{ "fuse_do_open", (void *)&klpe_fuse_do_open, "fuse" },
	{ "fuse_direct_io", (void *)&klpe_fuse_direct_io, "fuse" },
	{ "fuse_do_ioctl", (void *)&klpe_fuse_do_ioctl, "fuse" },
	{ "fuse_write_update_size", (void *)&klpe_fuse_write_update_size,
	  "fuse" },
	{ "fuse_wait_on_page_writeback",
	  (void *)&klpe_fuse_wait_on_page_writeback, "fuse" },
	{ "fuse_release_end", (void *)&klpe_fuse_release_end, "fuse" },
	{ "fuse_do_readpage", (void *)&klpe_fuse_do_readpage, "fuse" },
	{ "fuse_readpages_end", (void *)&klpe_fuse_readpages_end, "fuse" },
	{ "fuse_readpages_fill", (void *)&klpe_fuse_readpages_fill, "fuse" },
	{ "fuse_send_write", (void *)&klpe_fuse_send_write, "fuse" },
	{ "fuse_writepages_send", (void *)&klpe_fuse_writepages_send, "fuse" },
	{ "fuse_writepages_fill", (void *)&klpe_fuse_writepages_fill, "fuse" },
};

static int livepatch_bsc1184952_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1184952_module_nb = {
	.notifier_call = livepatch_bsc1184952_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1184952_fuse_file_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1184952_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1184952_fuse_file_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1184952_module_nb);
}
