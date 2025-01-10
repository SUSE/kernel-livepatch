/*
 * bsc1226324_net_xfrm_xfrm_policy
 *
 * Fix for CVE-2024-36971, bsc#1226324
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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

#include <net/dst.h>
#include <net/sock.h>
#include <linux/socket.h>

void klpp_xfrm_negative_advice(struct sock *sk, struct dst_entry *dst)
{
	if (dst->obsolete)
		sk_dst_reset(sk);
}

#include "bsc1226324_net_sock.h"

