/*
 * livepatch_bsc1269196
 *
 * Fix for CVE-2026-52972, bsc#1269196
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1269196.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from crypto/af_alg.c */
#include <linux/atomic.h>
#include <crypto/if_alg.h>

/* klp-ccp: from include/crypto/if_alg.h */
int klpp_af_alg_cmsg_send(struct msghdr *msg, struct af_alg_control *con);

/* klp-ccp: from crypto/af_alg.c */
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/rwsem.h>
#ifndef __GENKSYMS__
#include <linux/sched/signal.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <linux/security.h>

int klpp_af_alg_cmsg_send(struct msghdr *msg, struct af_alg_control *con)
{
	struct cmsghdr *cmsg;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;
		if (cmsg->cmsg_level != SOL_ALG)
			continue;

		switch (cmsg->cmsg_type) {
		case ALG_SET_IV:
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(*con->iv)))
				return -EINVAL;
			con->iv = (void *)CMSG_DATA(cmsg);
			if (cmsg->cmsg_len < CMSG_LEN(con->iv->ivlen +
						      sizeof(*con->iv)))
				return -EINVAL;
			break;

		case ALG_SET_OP:
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(u32)))
				return -EINVAL;
			con->op = *(u32 *)CMSG_DATA(cmsg);
			break;

		case ALG_SET_AEAD_ASSOCLEN:
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(u32)))
				return -EINVAL;
			con->aead_assoclen = *(u32 *)CMSG_DATA(cmsg);
			if (con->aead_assoclen >= 0x80000000u)
				return -EINVAL;
			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

typeof(klpp_af_alg_cmsg_send) klpp_af_alg_cmsg_send;


