/*
 * livepatch_bsc1272874
 *
 * Fix for CVE-2026-64217, bsc#1272874
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1272874.h"


/* klp-ccp: from fs/netfs/iterator.c */
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/scatterlist.h>
#include <linux/netfs.h>

/* klp-ccp: from include/linux/netfs.h */
/* klp-ccp: from fs/netfs/internal.h */
#include <linux/netfs.h>
#include <linux/fscache.h>
#include <trace/events/netfs.h>

/* klp-ccp: from fs/netfs/iterator.c */
ssize_t klpp_netfs_extract_user_iter(struct iov_iter *orig, size_t orig_len,
				struct iov_iter *new,
				iov_iter_extraction_t extraction_flags)
{
	struct bio_vec *bv = NULL;
	struct page **pages;
	unsigned int cur_npages;
	unsigned int max_pages;
	unsigned int npages = 0;
	unsigned int i;
	ssize_t ret;
	size_t count = orig_len, offset, len;
	size_t bv_size, pg_size;

	if (WARN_ON_ONCE(!iter_is_ubuf(orig) && !iter_is_iovec(orig)))
		return -EIO;

	max_pages = iov_iter_npages(orig, INT_MAX);
	bv_size = array_size(max_pages, sizeof(*bv));
	bv = kvmalloc(bv_size, GFP_KERNEL);
	if (!bv)
		return -ENOMEM;

	/* Put the page list at the end of the bvec list storage.  bvec
	 * elements are larger than page pointers, so as long as we work
	 * 0->last, we should be fine.
	 */
	pg_size = array_size(max_pages, sizeof(*pages));
	pages = (void *)bv + bv_size - pg_size;

	while (count && npages < max_pages) {
		ret = iov_iter_extract_pages(orig, &pages, count,
					     max_pages - npages, extraction_flags,
					     &offset);
		if (ret < 0) {
			pr_err("Couldn't get user pages (rc=%zd)\n", ret);
			break;
		}

		if (WARN(ret > count,
			 "%s: extract_pages overrun %zd > %zu bytes\n",
			 __func__, ret, count)) {
			ret = -EIO;
			break;
		}

		cur_npages = DIV_ROUND_UP(offset + ret, PAGE_SIZE);
		if (WARN(cur_npages > max_pages - npages,
			 "%s: extract_pages overrun %u > %u pages\n",
			 __func__, npages + cur_npages, max_pages)) {
			ret = -EIO;
			break;
		}

		count -= ret;
		ret += offset;

		for (i = 0; i < cur_npages; i++) {
			len = ret > PAGE_SIZE ? PAGE_SIZE : ret;
			bvec_set_page(bv + npages + i, *pages++, len - offset, offset);
			ret -= len;
			offset = 0;
		}

		npages += cur_npages;
	}

	/* Note: Don't try to clean up after EIO.  Either we got no pages, so
	 * nothing to clean up, or we got a buffer overrun, memory corruption
	 * and can't trust the stuff in the buffer (a WARN was emitted).
	 */

	iov_iter_bvec(new, orig->data_source, bv, npages, orig_len - count);
	return npages;
}



