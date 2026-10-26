/*
 * livepatch_bsc1280728
 *
 * Fix for CVE-2026-89551, bsc#1280728
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


#include "livepatch_bsc1280728.h"

/* klp-ccp: from net/sunrpc/xdr.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/errno.h>
#include <linux/sunrpc/xdr.h>

/* klp-ccp: from net/sunrpc/xdr.c */
#include <linux/sunrpc/msg_prot.h>

void klpp_xdr_buf_trim(struct xdr_buf *buf, unsigned int len)
{
	size_t cur;
	unsigned int trim = len;

	if (buf->tail[0].iov_len) {
		cur = min_t(size_t, buf->tail[0].iov_len, trim);
		buf->tail[0].iov_len -= cur;
		trim -= cur;
		if (!trim)
			goto fix_len;
	}

	if (buf->page_len) {
		cur = min_t(unsigned int, buf->page_len, trim);
		buf->page_len -= cur;
		trim -= cur;
		if (!trim)
			goto fix_len;
	}

	if (buf->head[0].iov_len) {
		cur = min_t(size_t, buf->head[0].iov_len, trim);
		buf->head[0].iov_len -= cur;
		trim -= cur;
	}
fix_len:
	buf->len -= min_t(unsigned int, buf->len, len - trim);
}



