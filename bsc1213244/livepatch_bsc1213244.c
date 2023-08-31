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
#include <linux/init.h>
#include <linux/vt_kern.h>
#include <linux/selection.h>

/* klp-ccp: from include/linux/selection.h */
static void (*klpe_getconsxy)(const struct vc_data *vc, unsigned char xy[static 2]);

static u16 (*klpe_vcs_scr_readw)(const struct vc_data *vc, const u16 *org);

static int (*klpe_vc_uniscr_check)(struct vc_data *vc);
static void (*klpe_vc_uniscr_copy_line)(const struct vc_data *vc, void *dest,
				bool viewed,
				unsigned int row, unsigned int col,
				unsigned int nr);

/* klp-ccp: from drivers/tty/vt/vc_screen.c */
#include <linux/console.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/signal.h>
#include <linux/notifier.h>
#include <linux/uaccess.h>
#include <asm/byteorder.h>

#define HEADER_SIZE	4u
#define CON_BUF_SIZE (CONFIG_BASE_SMALL ? 256 : PAGE_SIZE)

#define console(inode)		(iminor(inode) & 63)
#define use_unicode(inode)	(iminor(inode) & 64)
#define use_attributes(inode)	(iminor(inode) & 128)

struct vcs_poll_data {
	struct notifier_block notifier;
	unsigned int cons_num;
	int event;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
};

static struct vc_data *vcs_vc(struct inode *inode, bool *viewed)
{
	unsigned int currcons = console(inode);

	WARN_CONSOLE_UNLOCKED();

	if (currcons == 0) {
		currcons = fg_console;
		if (viewed)
			*viewed = true;
	} else {
		currcons--;
		if (viewed)
			*viewed = false;
	}
	return vc_cons[currcons].d;
}

static int (*klpe_vcs_size)(const struct vc_data *vc, bool attr, bool unicode);

static int klpr_vcs_read_buf_uni(struct vc_data *vc, char *con_buf,
		unsigned int pos, unsigned int count, bool viewed)
{
	unsigned int nr, row, col, maxcol = vc->vc_cols;
	int ret;

	ret = (*klpe_vc_uniscr_check)(vc);
	if (ret)
		return ret;

	pos /= 4;
	row = pos / maxcol;
	col = pos % maxcol;
	nr = maxcol - col;
	do {
		if (nr > count / 4)
			nr = count / 4;
		(*klpe_vc_uniscr_copy_line)(vc, con_buf, viewed, row, col, nr);
		con_buf += nr * 4;
		count -= nr * 4;
		row++;
		col = 0;
		nr = maxcol;
	} while (count);

	return 0;
}

static void klpr_vcs_read_buf_noattr(const struct vc_data *vc, char *con_buf,
		unsigned int pos, unsigned int count, bool viewed)
{
	u16 *org;
	unsigned int col, maxcol = vc->vc_cols;

	org = screen_pos(vc, pos, viewed);
	col = pos % maxcol;
	pos += maxcol - col;

	while (count-- > 0) {
		*con_buf++ = ((*klpe_vcs_scr_readw)(vc, org++) & 0xff);
		if (++col == maxcol) {
			org = screen_pos(vc, pos, viewed);
			col = 0;
			pos += maxcol;
		}
	}
}

static unsigned int klpr_vcs_read_buf(const struct vc_data *vc, char *con_buf,
		unsigned int pos, unsigned int count, bool viewed,
		unsigned int *skip)
{
	u16 *org, *con_buf16;
	unsigned int col, maxcol = vc->vc_cols;
	unsigned int filled = count;

	if (pos < HEADER_SIZE) {
		/* clamp header values if they don't fit */
		con_buf[0] = min(vc->vc_rows, 0xFFu);
		con_buf[1] = min(vc->vc_cols, 0xFFu);
		(*klpe_getconsxy)(vc, con_buf + 2);

		*skip += pos;
		count += pos;
		if (count > CON_BUF_SIZE) {
			count = CON_BUF_SIZE;
			filled = count - pos;
		}

		/* Advance state pointers and move on. */
		count -= min(HEADER_SIZE, count);
		pos = HEADER_SIZE;
		con_buf += HEADER_SIZE;
		/* If count >= 0, then pos is even... */
	} else if (pos & 1) {
		/*
		 * Skip first byte for output if start address is odd. Update
		 * region sizes up/down depending on free space in buffer.
		 */
		(*skip)++;
		if (count < CON_BUF_SIZE)
			count++;
		else
			filled--;
	}

	if (!count)
		return filled;

	pos -= HEADER_SIZE;
	pos /= 2;
	col = pos % maxcol;

	org = screen_pos(vc, pos, viewed);
	pos += maxcol - col;

	/*
	 * Buffer has even length, so we can always copy character + attribute.
	 * We do not copy last byte to userspace if count is odd.
	 */
	count = (count + 1) / 2;
	con_buf16 = (u16 *)con_buf;

	while (count) {
		*con_buf16++ = (*klpe_vcs_scr_readw)(vc, org++);
		count--;
		if (++col == maxcol) {
			org = screen_pos(vc, pos, viewed);
			col = 0;
			pos += maxcol;
		}
	}

	return filled;
}

ssize_t
klpp_vcs_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	struct vc_data *vc;
	struct vcs_poll_data *poll;
	unsigned int read;
	ssize_t ret;
	char *con_buf;
	loff_t pos;
	bool viewed, attr, uni_mode;

	con_buf = (char *) __get_free_page(GFP_KERNEL);
	if (!con_buf)
		return -ENOMEM;

	pos = *ppos;

	/* Select the proper current console and verify
	 * sanity of the situation under the console lock.
	 */
	console_lock();

	uni_mode = use_unicode(inode);
	attr = use_attributes(inode);

	ret = -EINVAL;
	if (pos < 0)
		goto unlock_out;
	/* we enforce 32-bit alignment for pos and count in unicode mode */
	if (uni_mode && (pos | count) & 3)
		goto unlock_out;

	poll = file->private_data;
	if (count && poll)
		poll->event = 0;
	read = 0;
	ret = 0;
	while (count) {
		unsigned int this_round, skip = 0;
		int size;

		vc = vcs_vc(inode, &viewed);
		if (!vc) {
			ret = -ENXIO;
			break;
		}

		/* Check whether we are above size each round,
		 * as copy_to_user at the end of this loop
		 * could sleep.
		 */
		size = (*klpe_vcs_size)(vc, attr, uni_mode);
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

		if (uni_mode) {
			ret = klpr_vcs_read_buf_uni(vc, con_buf, pos, this_round,
					viewed);
			if (ret)
				break;
		} else if (!attr) {
			klpr_vcs_read_buf_noattr(vc, con_buf, pos, this_round,
					viewed);
		} else {
			this_round = klpr_vcs_read_buf(vc, con_buf, pos, this_round,
					viewed, &skip);
		}

		/* Finally, release the console semaphore while we push
		 * all the data to userspace from our temporary buffer.
		 *
		 * AKPM: Even though it's a semaphore, we should drop it because
		 * the pagefault handling code may want to call printk().
		 */

		console_unlock();
		ret = copy_to_user(buf, con_buf + skip, this_round);
		console_lock();

		if (ret) {
			read += this_round - ret;
			ret = -EFAULT;
			break;
		}
		buf += this_round;
		pos += this_round;
		read += this_round;
		count -= this_round;
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
	{ "vc_uniscr_check", (void *)&klpe_vc_uniscr_check },
	{ "vc_uniscr_copy_line", (void *)&klpe_vc_uniscr_copy_line },
	{ "vcs_scr_readw", (void *)&klpe_vcs_scr_readw },
	{ "vcs_size", (void *)&klpe_vcs_size },
};


int livepatch_bsc1213244_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

