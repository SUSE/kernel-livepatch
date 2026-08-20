/*
 * bsc1253437_net_sctp_bind_addr
 *
 * Fix for CVE-2025-40204, bsc#1253437
 * Fix for CVE-2026-53224, bsc#1270023
 * Fix for CVE-2026-53246, bsc#1270024
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


#include "livepatch_bsc1253437.h"


/* klp-ccp: from net/sctp/bind_addr.c */
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/ipv6.h>
#include <net/if_inet6.h>
#include <net/sctp/sctp.h>

/* klp-ccp: from include/net/sctp/structs.h */
int klpp_sctp_raw_to_bind_addrs(struct sctp_bind_addr *bp, __u8 *raw, int len,
			   __u16 port, gfp_t gfp);

/* klp-ccp: from net/sctp/bind_addr.c */
#include <net/sctp/sm.h>

static void sctp_bind_addr_clean(struct sctp_bind_addr *);

static void sctp_bind_addr_clean(struct sctp_bind_addr *bp)
{
	struct sctp_sockaddr_entry *addr, *temp;

	/* Empty the bind address list. */
	list_for_each_entry_safe(addr, temp, &bp->address_list, list) {
		list_del_rcu(&addr->list);
		kfree_rcu(addr, rcu);
		SCTP_DBG_OBJCNT_DEC(addr);
	}
}

int sctp_add_bind_addr(struct sctp_bind_addr *bp, union sctp_addr *new,
		       int new_size, __u8 addr_state, gfp_t gfp);

int klpp_sctp_raw_to_bind_addrs(struct sctp_bind_addr *bp, __u8 *raw_addr_list,
			   int addrs_len, __u16 port, gfp_t gfp)
{
	union sctp_addr_param *rawaddr;
	struct sctp_paramhdr *param;
	union sctp_addr addr;
	int retval = 0;
	int len;
	struct sctp_af *af;

	/* Convert the raw address to standard address format */
	while (addrs_len) {
		param = (struct sctp_paramhdr *)raw_addr_list;
		rawaddr = (union sctp_addr_param *)raw_addr_list;

		if (addrs_len < sizeof(*param)) {
			retval = -EINVAL;
			goto out_err;
		}
		len = ntohs(param->length);
		if (addrs_len < len) {
			retval = -EINVAL;
			goto out_err;
		}

		af = sctp_get_af_specific(param_type2af(param->type));
		if (unlikely(!af) ||
		    !af->from_addr_param(&addr, rawaddr, htons(port), 0)) {
			retval = -EINVAL;
			goto out_err;
		}

		if (sctp_bind_addr_state(bp, &addr) != -1)
			goto next;
		retval = sctp_add_bind_addr(bp, &addr, sizeof(addr),
					    SCTP_ADDR_SRC, gfp);
		if (retval)
			/* Can't finish building the list, clean up. */
			goto out_err;

next:
		addrs_len -= len;
		raw_addr_list += len;
	}

	return retval;

out_err:
	if (retval)
		sctp_bind_addr_clean(bp);

	return retval;
}

int sctp_bind_addr_state(const struct sctp_bind_addr *bp,
			 const union sctp_addr *addr);


#include <linux/livepatch.h>

extern typeof(sctp_add_bind_addr) sctp_add_bind_addr
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_add_bind_addr);
extern typeof(sctp_bind_addr_state) sctp_bind_addr_state
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_bind_addr_state);
extern typeof(sctp_get_af_specific) sctp_get_af_specific
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_get_af_specific);
