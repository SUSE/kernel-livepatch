/*
 * livepatch_bsc1266265
 *
 * Fix for CVE-2026-46243, bsc#1266265
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1266265.h"


/* klp-ccp: from fs/smb/client/cifs_spnego.c */
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <keys/user-type.h>
#include <linux/key-type.h>
#include <linux/keyctl.h>
#include <linux/inet.h>
/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
#include <linux/utsname.h>
#include <linux/sched/mm.h>
#include <linux/netfs.h>
/* klp-ccp: from fs/smb/client/cifs_fs_sb.h */
#include <linux/rbtree.h>

#ifndef _CIFS_FS_SB_H

#include <linux/backing-dev.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif				/* _CIFS_FS_SB_H */

/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <crypto/internal/hash.h>
#include <uapi/linux/cifs/cifs_mount.h>
/* klp-ccp: from fs/smb/client/smb2pdu.h */
#include <net/sock.h>
/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <linux/filelock.h>
/* klp-ccp: from fs/smb/client/cifspdu.h */
#include <net/sock.h>
/* klp-ccp: from fs/smb/client/cifsproto.h */
#include <linux/nls.h>
#include <linux/ctype.h>

/* klp-ccp: from fs/smb/client/trace.h */
#if !defined(_CIFS_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>
#include <linux/net.h>
#include <linux/inet.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _CIFS_TRACE_H */

#include <trace/define_trace.h>
/* klp-ccp: from fs/smb/client/cifsproto.h */
#ifdef CONFIG_CIFS_DFS_UPCALL

/* klp-ccp: from fs/smb/client/dfs_cache.h */
#include <linux/nls.h>
#include <linux/list.h>
#include <linux/uuid.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from fs/smb/client/cifsproto.h */
#endif

/* klp-ccp: from fs/smb/client/cifs_spnego.c */
void
klpp_cifs_spnego_key_destroy(struct key *key)
{
	kfree(key->payload.data[0]);
}
