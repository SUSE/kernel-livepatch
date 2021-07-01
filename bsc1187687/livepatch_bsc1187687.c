/*
 * livepatch_bsc1187687
 *
 * Fix for CVE-2021-0605, bsc#1187687
 *
 *  Upstream commit:
 *  37bd22420f85 ("af_key: pfkey_dump needs parameter validation")
 *
 *  SLE12-SP3 commit:
 *  237f8521e52fa170713bea566f7aa458e7e49739
 *
 *  SLE12-SP4 and SLE15 commit:
 *  685407abac934bafd8dd05a2013d19cb234f17f4
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  0611b53d0e6358af1ce99163f64e3a0b6a9bac69
 *
 *  SLE15-SP2 and -SP3 commit:
 *  f22517a43f2b62cf2258f06bb0dc3a0002362fcc
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

/* klp-ccp: from net/key/af_key.c */
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/pfkeyv2.h>
#include <uapi/linux/ipsec.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <net/xfrm.h>
#include <net/sock.h>

struct pfkey_sock {
	/* struct sock must be the first member of struct pfkey_sock */
	struct sock	sk;
	int		registered;
	int		promisc;

	struct {
		uint8_t		msg_version;
		uint32_t	msg_portid;
		int		(*dump)(struct pfkey_sock *sk);
		void		(*done)(struct pfkey_sock *sk);
		union {
			struct xfrm_policy_walk	policy;
			struct xfrm_state_walk	state;
		} u;
		struct sk_buff	*skb;
	} dump;
	struct mutex dump_lock;
};

static inline struct pfkey_sock *pfkey_sk(struct sock *sk)
{
	return (struct pfkey_sock *)sk;
}

static int (*klpe_pfkey_do_dump)(struct pfkey_sock *pfk);

static uint16_t
pfkey_satype2proto(uint8_t satype)
{
	switch (satype) {
	case SADB_SATYPE_UNSPEC:
		return IPSEC_PROTO_ANY;
	case SADB_SATYPE_AH:
		return IPPROTO_AH;
	case SADB_SATYPE_ESP:
		return IPPROTO_ESP;
	case SADB_X_SATYPE_IPCOMP:
		return IPPROTO_COMP;
	default:
		return 0;
	}
	/* NOTREACHED */
}

static int (*klpe_pfkey_dump_sa)(struct pfkey_sock *pfk);

static void (*klpe_pfkey_dump_sa_done)(struct pfkey_sock *pfk);

int klpp_pfkey_dump(struct sock *sk, struct sk_buff *skb, const struct sadb_msg *hdr, void * const *ext_hdrs)
{
	u8 proto;
	struct xfrm_address_filter *filter = NULL;
	struct pfkey_sock *pfk = pfkey_sk(sk);

	mutex_lock(&pfk->dump_lock);
	if (pfk->dump.dump != NULL) {
		mutex_unlock(&pfk->dump_lock);
		return -EBUSY;
	}

	proto = pfkey_satype2proto(hdr->sadb_msg_satype);
	if (proto == 0) {
		mutex_unlock(&pfk->dump_lock);
		return -EINVAL;
	}

	if (ext_hdrs[SADB_X_EXT_FILTER - 1]) {
		struct sadb_x_filter *xfilter = ext_hdrs[SADB_X_EXT_FILTER - 1];

		/*
		 * Fix CVE-2021-0605
		 *  +7 lines
		 */
		if ((xfilter->sadb_x_filter_splen >=
			(sizeof(xfrm_address_t) << 3)) ||
		    (xfilter->sadb_x_filter_dplen >=
			(sizeof(xfrm_address_t) << 3))) {
			mutex_unlock(&pfk->dump_lock);
			return -EINVAL;
		}
		filter = kmalloc(sizeof(*filter), GFP_KERNEL);
		if (filter == NULL) {
			mutex_unlock(&pfk->dump_lock);
			return -ENOMEM;
		}

		memcpy(&filter->saddr, &xfilter->sadb_x_filter_saddr,
		       sizeof(xfrm_address_t));
		memcpy(&filter->daddr, &xfilter->sadb_x_filter_daddr,
		       sizeof(xfrm_address_t));
		filter->family = xfilter->sadb_x_filter_family;
		filter->splen = xfilter->sadb_x_filter_splen;
		filter->dplen = xfilter->sadb_x_filter_dplen;
	}

	pfk->dump.msg_version = hdr->sadb_msg_version;
	pfk->dump.msg_portid = hdr->sadb_msg_pid;
	pfk->dump.dump = (*klpe_pfkey_dump_sa);
	pfk->dump.done = (*klpe_pfkey_dump_sa_done);
	xfrm_state_walk_init(&pfk->dump.u.state, proto, filter);
	mutex_unlock(&pfk->dump_lock);

	return (*klpe_pfkey_do_dump)(pfk);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1187687.h"
#include "../kallsyms_relocs.h"

#if IS_MODULE(CONFIG_NET_KEY)

#define LIVEPATCHED_MODULE "af_key"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "pfkey_do_dump", (void *)&klpe_pfkey_do_dump, "af_key" },
	{ "pfkey_dump_sa", (void *)&klpe_pfkey_dump_sa, "af_key" },
	{ "pfkey_dump_sa_done", (void *)&klpe_pfkey_dump_sa_done, "af_key" },
};

static int livepatch_bsc1187687_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1187687_module_nb = {
	.notifier_call = livepatch_bsc1187687_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1187687_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1187687_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1187687_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1187687_module_nb);
}

#else /* !IS_MODULE(CONFIG_NET_KEY) */

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "pfkey_do_dump", (void *)&klpe_pfkey_do_dump },
	{ "pfkey_dump_sa", (void *)&klpe_pfkey_dump_sa },
	{ "pfkey_dump_sa_done", (void *)&klpe_pfkey_dump_sa_done },
};

int livepatch_bsc1187687_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_MODULE(CONFIG_NET_KEY) */
