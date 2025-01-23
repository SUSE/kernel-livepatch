/*
 * bsc1229275_fs_cachefiles_volume
 *
 * Fix for CVE-2024-41057, bsc#1229275
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from fs/cachefiles/volume.c */
#include <linux/fs.h>
#include <linux/slab.h>

/* klp-ccp: from fs/cachefiles/internal.h */
#include <linux/fscache-cache.h>
#include <linux/cred.h>

#include <linux/xarray.h>

struct cachefiles_volume {
	struct cachefiles_cache		*cache;
	struct list_head		cache_link;	/* Link in cache->volumes */
	struct fscache_volume		*vcookie;	/* The netfs's representation */
	struct dentry			*dentry;	/* The volume dentry */
	struct dentry			*fanout[256];	/* Fanout subdirs */
};

extern bool cachefiles_set_volume_xattr(struct cachefiles_volume *volume);

/* klp-ccp: from fs/cachefiles/volume.c */
extern void __cachefiles_free_volume(struct cachefiles_volume *volume);

void klpp_cachefiles_withdraw_volume(struct cachefiles_volume *volume)
{
	cachefiles_set_volume_xattr(volume);
	__cachefiles_free_volume(volume);
}

#include "livepatch_bsc1229275.h"

#include <linux/livepatch.h>

extern typeof(__cachefiles_free_volume) __cachefiles_free_volume
	 KLP_RELOC_SYMBOL(cachefiles, cachefiles, __cachefiles_free_volume);
extern typeof(cachefiles_set_volume_xattr) cachefiles_set_volume_xattr
	 KLP_RELOC_SYMBOL(cachefiles, cachefiles, cachefiles_set_volume_xattr);
