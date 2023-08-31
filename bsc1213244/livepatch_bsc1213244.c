/*
 * livepatch_bsc1213244
 *
 * Fix for CVE-2023-3567, bsc#1213244
 *
 *  Upstream commit:
 *  226fae124b2d ("vc_screen: move load of struct vc_data pointer in vcs_read() to avoid UAF")
 *  ae3419fbac84 ("vc_screen: don't clobber return value in vcs_read")
 *  46d733d0efc7 ("vc_screen: modify vcs_size() handling in vcs_read()")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  3f1b17ce604b13c6d1e343614462de5c7e33d45b
 *  ae5923a630ef9fb4d87afa1c469daa298586a6a6
 *  d1352c96a85641c5845f2e3c0280a727bd8770ce
 *
 *  SLE15-SP2 and -SP3 commit:
 *  1f3f7780a4dac23518d07f9e63d98e4423241c8a
 *  2443e93fac648016422ebd3156c422a78132ec35
 *  da930b7b43be8e6d97f1473c4e1979d202963a96
 *
 *  SLE15-SP4 and -SP5 commit:
 *  93bb34e58a22fc74a8241ebed9479f648f922de3
 *  1b179588bfbe646e5bbb82c87e1d5bc1b98a7043
 *  833f09169c64bf5e111a28ca4d620b4cc59b8587
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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



/* klp-ccp: from drivers/tty/vt/vc_screen.c */
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/tty.h>
#include <linux/init.h>
#include <linux/vt_kern.h>
#include <linux/selection.h>

/* klp-ccp: from include/linux/selection.h */
static void (*klpe_getconsxy)(struct vc_data *vc, unsigned char *p);

static u16 (*klpe_vcs_scr_readw)(struct vc_data *vc, const u16 *org);

/* klp-ccp: from drivers/tty/vt/vc_screen.c */
#include <linux/console.h>

/* klp-ccp: from include/linux/console.h */
static int (*klpe_is_console_locked)(void);

#define KLPP_WARN_CONSOLE_UNLOCKED()	WARN_ON(!klpe_is_console_locked() && !oops_in_progress)

/* klp-ccp: from drivers/tty/vt/vc_screen.c */
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/notifier.h>
#include <linux/uaccess.h>
#include <asm/byteorder.h>

#define HEADER_SIZE	4

#define CON_BUF_SIZE (CONFIG_BASE_SMALL ? 256 : PAGE_SIZE)

struct vcs_poll_data {
	struct notifier_block notifier;
	unsigned int cons_num;
	bool seen_last_update;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
};

static struct vc_data*
klpr_vcs_vc(struct inode *inode, int *viewed)
{
	unsigned int currcons = iminor(inode) & 127;

	KLPP_WARN_CONSOLE_UNLOCKED();

	if (currcons == 0) {
		currcons = fg_console;
		if (viewed)
			*viewed = 1;
	} else {
		currcons--;
		if (viewed)
			*viewed = 0;
	}
	return vc_cons[currcons].d;
}

static int
(*klpe_vcs_size)(struct inode *inode);

ssize_t
klpp_vcs_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	unsigned int currcons = iminor(inode);
	struct vc_data *vc;
	struct vcs_poll_data *poll;
	long pos;
	long attr, read;
	int col, maxcol, viewed;
	unsigned short *org = NULL;
	ssize_t ret;
	char *con_buf;

	con_buf = (char *) __get_free_page(GFP_KERNEL);
	if (!con_buf)
		return -ENOMEM;

	pos = *ppos;

	/* Select the proper current console and verify
	 * sanity of the situation under the console lock.
	 */
	console_lock();

	attr = (currcons & 128);

	ret = -EINVAL;
	if (pos < 0)
		goto unlock_out;
	poll = file->private_data;
	if (count && poll)
		poll->seen_last_update = true;
	read = 0;
	ret = 0;
	while (count) {
		char *con_buf0, *con_buf_start;
		long this_round, size;
		ssize_t orig_count;
		long p = pos;

		vc = klpr_vcs_vc(inode, &viewed);
		if (!vc) {
			ret = -ENXIO;
			break;
		}

		/* Check whether we are above size each round,
		 * as copy_to_user at the end of this loop
		 * could sleep.
		 */
		size = (*klpe_vcs_size)(inode);
		if (size < 0) {
			ret = size;
			break;
		}
		if (pos >= size)
			break;
		if (count > size - pos)
			count = size - pos;

		this_round = count;
		if (this_round > CON_BUF_SIZE)
			this_round = CON_BUF_SIZE;

		/* Perform the whole read into the local con_buf.
		 * Then we can drop the console spinlock and safely
		 * attempt to move it to userspace.
		 */

		con_buf_start = con_buf0 = con_buf;
		orig_count = this_round;
		maxcol = vc->vc_cols;
		if (!attr) {
			org = screen_pos(vc, p, viewed);
			col = p % maxcol;
			p += maxcol - col;
			while (this_round-- > 0) {
				*con_buf0++ = ((*klpe_vcs_scr_readw)(vc, org++) & 0xff);
				if (++col == maxcol) {
					org = screen_pos(vc, p, viewed);
					col = 0;
					p += maxcol;
				}
			}
		} else {
			if (p < HEADER_SIZE) {
				size_t tmp_count;

				con_buf0[0] = (char)vc->vc_rows;
				con_buf0[1] = (char)vc->vc_cols;
				(*klpe_getconsxy)(vc, con_buf0 + 2);

				con_buf_start += p;
				this_round += p;
				if (this_round > CON_BUF_SIZE) {
					this_round = CON_BUF_SIZE;
					orig_count = this_round - p;
				}

				tmp_count = HEADER_SIZE;
				if (tmp_count > this_round)
					tmp_count = this_round;

				/* Advance state pointers and move on. */
				this_round -= tmp_count;
				p = HEADER_SIZE;
				con_buf0 = con_buf + HEADER_SIZE;
				/* If this_round >= 0, then p is even... */
			} else if (p & 1) {
				/* Skip first byte for output if start address is odd
				 * Update region sizes up/down depending on free
				 * space in buffer.
				 */
				con_buf_start++;
				if (this_round < CON_BUF_SIZE)
					this_round++;
				else
					orig_count--;
			}
			if (this_round > 0) {
				unsigned short *tmp_buf = (unsigned short *)con_buf0;

				p -= HEADER_SIZE;
				p /= 2;
				col = p % maxcol;

				org = screen_pos(vc, p, viewed);
				p += maxcol - col;

				/* Buffer has even length, so we can always copy
				 * character + attribute. We do not copy last byte
				 * to userspace if this_round is odd.
				 */
				this_round = (this_round + 1) >> 1;

				while (this_round) {
					*tmp_buf++ = (*klpe_vcs_scr_readw)(vc, org++);
					this_round --;
					if (++col == maxcol) {
						org = screen_pos(vc, p, viewed);
						col = 0;
						p += maxcol;
					}
				}
			}
		}

		/* Finally, release the console semaphore while we push
		 * all the data to userspace from our temporary buffer.
		 *
		 * AKPM: Even though it's a semaphore, we should drop it because
		 * the pagefault handling code may want to call printk().
		 */

		console_unlock();
		ret = copy_to_user(buf, con_buf_start, orig_count);
		console_lock();

		if (ret) {
			read += (orig_count - ret);
			ret = -EFAULT;
			break;
		}
		buf += orig_count;
		pos += orig_count;
		read += orig_count;
		count -= orig_count;
	}
	*ppos += read;
	if (read)
		ret = read;
unlock_out:
	console_unlock();
	free_page((unsigned long) con_buf);
	return ret;
}


#include "livepatch_bsc1213244.h"
#include <linux/kernel.h>
#include "../kallsyms_relocs.h"


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "getconsxy", (void *)&klpe_getconsxy },
	{ "is_console_locked", (void *)&klpe_is_console_locked },
	{ "vcs_scr_readw", (void *)&klpe_vcs_scr_readw },
	{ "vcs_size", (void *)&klpe_vcs_size },
};


int livepatch_bsc1213244_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

