/*
 * livepatch_bsc1233712
 *
 * Fix for CVE-2024-50264, bsc#1233712
 *
 *  Upstream commit:
 *  6ca575374dd9 ("vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans")
 *
 *  SLE12-SP5 commit:
 *  edf6fa0e28079cf2df71bf0b8539f8b1b549519a
 *
 *  SLE15-SP2 and -SP3 commit:
 *  131f00cf9f077994c1ee328e4dbb800bd8b51416
 *
 *  SLE15-SP4 and -SP5 commit:
 *  008fbbff8c183e272507108cc5739597e451107b
 *
 *  SLE15-SP6 commit:
 *  2855c61c141e5245b636b7a7c242f36e34ebcfa6
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_VIRTIO_VSOCKETS_COMMON)

#if !IS_MODULE(CONFIG_VIRTIO_VSOCKETS_COMMON)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/vmw_vsock/virtio_transport_common.c */
#include <linux/virtio_vsock.h>
/* klp-ccp: from net/vmw_vsock/virtio_transport_common.c */
#include <net/af_vsock.h>

/* needed for kfree */
#include <linux/slab.h>

/* klp-ccp: from net/vmw_vsock/virtio_transport_common.c */
void klpp_virtio_transport_destruct(struct vsock_sock *vsk)
{
	struct virtio_vsock_sock *vvs = vsk->trans;

	kfree(vvs);
	vsk->trans = NULL;
}

typeof(klpp_virtio_transport_destruct) klpp_virtio_transport_destruct;

#include "livepatch_bsc1233712.h"

#endif /* IS_ENABLED() */
