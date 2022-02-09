/*
 * livepatch_bsc1194460
 *
 * Fix for CVE-2021-4083, bsc#1194460
 *
 *  Upstream commits:
 *  054aa8d439b9 ("fget: check that the fd still exists after getting a ref to
 *                 it")
 *  e386dfc56f83 ("fget: clarify and improve __fget_files() implementation")
 *
 *  SLE12-SP3 commits:
 *  e9025bffcac308009d883451319f31afbd852014
 *  696ea54330728834f1f405a6c4272b2d4b036bf9
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  54415991a84809ce489151c17a7122e6011b4d0a
 *  3ce5a50ec307c25dc5e7bc65b21940969890c32b
 *
 *  SLE15-SP2 and -SP3 commits:
 *  9958eaea97fb97b08c1126fe52af0663bed53723
 *  4b3242f915c813cfa6226445f83b8c3f982311f8
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#include <linux/file.h>

/* klp-ccp: from fs/file.c */
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/time.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>

static struct file *klpp___fget_rcu(unsigned int fd, fmode_t mask)
{
	struct files_struct *files = current->files;

	for (;;) {
		struct file *file;
		struct fdtable *fdt = rcu_dereference_raw(files->fdt);
		struct file __rcu **fdentry;

		if (unlikely(fd >= fdt->max_fds))
			return NULL;

		fdentry = fdt->fd + array_index_nospec(fd, fdt->max_fds);
		file = rcu_dereference_raw(*fdentry);
		if (unlikely(!file))
			return NULL;

		if (unlikely(file->f_mode & mask))
			return NULL;

		/*
		 * Ok, we have a file pointer. However, because we do
		 * this all locklessly under RCU, we may be racing with
		 * that file being closed.
		 *
		 * Such a race can take two forms:
		 *
		 *  (a) the file ref already went down to zero,
		 *      and get_file_rcu_many() fails. Just try
		 *      again:
		 */
		if (unlikely(!get_file_rcu(file)))
			continue;

		/*
		 *  (b) the file table entry has changed under us.
		 *      Note that we don't need to re-check the 'fdt->fd'
		 *      pointer having changed, because it always goes
		 *      hand-in-hand with 'fdt'.
		 *
		 * If so, we need to put our refs and try again.
		 */
		if (unlikely(rcu_dereference_raw(files->fdt) != fdt) ||
		    unlikely(rcu_dereference_raw(*fdentry) != file)) {
			fput(file);
			continue;
		}

		/*
		 * Ok, we have a ref to the file, and checked that it
		 * still exists.
		 */
		return file;
	}
}

struct file *klpp___fget(unsigned int fd, fmode_t mask)
{
	struct file *file;

	rcu_read_lock();
	file = klpp___fget_rcu(fd, mask);
	rcu_read_unlock();

	return file;
}



#include "livepatch_bsc1194460.h"
