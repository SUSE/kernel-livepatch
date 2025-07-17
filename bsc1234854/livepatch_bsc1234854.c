/*
 * livepatch_bsc1234854
 *
 * Fix for CVE-2024-53146, bsc#1234854
 *
 *  Upstream commit:
 *  7f33b92e5b18 ("NFSD: Prevent a potential integer overflow")
 *
 *  SLE12-SP5 commit:
 *  c43d88d67d495240f84924886b800256c3d4d76c
 *
 *  SLE15-SP3 commit:
 *  eb512aa271c4678624e81a7d019f1e1407f4ca00
 *
 *  SLE15-SP4 and -SP5 commit:
 *  79b751c0d4af68e96a0d96b7afed040fecbaa158
 *
 *  SLE15-SP6 commit:
 *  1b6cbfa2fe3204a6fe4079e078f915ae0ed40e74
 *
 *  SLE MICRO-6-0 commit:
 *  1b6cbfa2fe3204a6fe4079e078f915ae0ed40e74
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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


/* klp-ccp: from fs/nfsd/nfs4callback.c */
#include <linux/sunrpc/clnt.h>

/* klp-ccp: from include/linux/sunrpc/debug.h */
#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)

static unsigned int		(*klpe_nfsd_debug);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from include/linux/sunrpc/xdr.h */
#ifdef __KERNEL__

static __be32 *(*klpe_xdr_inline_decode)(struct xdr_stream *xdr, size_t nbytes);

static inline ssize_t
klpr_xdr_stream_decode_u32(struct xdr_stream *xdr, __u32 *ptr)
{
	const size_t count = sizeof(*ptr);
	__be32 *p = (*klpe_xdr_inline_decode)(xdr, count);

	if (unlikely(!p))
		return -EBADMSG;
	*ptr = be32_to_cpup(p);
	return 0;
}

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __KERNEL__ */

/* klp-ccp: from fs/nfsd/nfs4callback.c */
#include <linux/sunrpc/xprt.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/slab.h>

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/types.h>

#include <linux/nfs4.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/msg_prot.h>

#include <uapi/linux/nfsd/debug.h>

/* klp-ccp: from fs/nfsd/stats.h */
#include <uapi/linux/nfsd/stats.h>

/* klp-ccp: from fs/nfsd/export.h */
#include <linux/sunrpc/cache.h>
#include <uapi/linux/nfsd/export.h>
#include <linux/nfs4.h>

/* klp-ccp: from fs/nfsd/state.h */
#include <linux/idr.h>
#include <linux/sunrpc/svc_xprt.h>

/* klp-ccp: from fs/nfsd/nfsfh.h */
#include <linux/sunrpc/svc.h>

/* klp-ccp: from fs/nfsd/state.h */
typedef struct {
	u32             cl_boot;
	u32             cl_id;
} clientid_t;

struct nfsd4_callback {
	struct nfs4_client *cb_clp;
	struct rpc_message cb_msg;
	const struct nfsd4_callback_ops *cb_ops;
	struct work_struct cb_work;
	int cb_seq_status;
	int cb_status;
	bool cb_need_restart;
	bool cb_holds_slot;
};

struct nfs4_cb_conn {
	/* SETCLIENTID info */
	struct sockaddr_storage	cb_addr;
	struct sockaddr_storage	cb_saddr;
	size_t			cb_addrlen;
	u32                     cb_prog; /* used only in 4.0 case;
					    per-session otherwise */
	u32                     cb_ident;	/* minorversion 0 only */
	struct svc_xprt		*cb_xprt;	/* minorversion 1 only */
};

struct nfsd4_channel_attrs {
	u32		headerpadsz;
	u32		maxreq_sz;
	u32		maxresp_sz;
	u32		maxresp_cached;
	u32		maxops;
	u32		maxreqs;
	u32		nr_rdma_attrs;
	u32		rdma_attrs;
};

struct nfsd4_cb_sec {
	u32	flavor; /* (u32)(-1) used to mean "no valid flavor" */
	kuid_t	uid;
	kgid_t	gid;
};

struct nfsd4_create_session {
	clientid_t			clientid;
	struct nfs4_sessionid		sessionid;
	u32				seqid;
	u32				flags;
	struct nfsd4_channel_attrs	fore_channel;
	struct nfsd4_channel_attrs	back_channel;
	u32				callback_prog;
	struct nfsd4_cb_sec		cb_sec;
};

struct nfsd4_clid_slot {
	u32				sl_seqid;
	__be32				sl_status;
	struct nfsd4_create_session	sl_cr_ses;
};

struct nfsd4_session {
	atomic_t		se_ref;
	struct list_head	se_hash;	/* hash by sessionid */
	struct list_head	se_perclnt;
/* See SESSION4_PERSIST, etc. for standard flags; this is internal-only: */
	u32			se_flags;
	struct nfs4_client	*se_client;
	struct nfs4_sessionid	se_sessionid;
	struct nfsd4_channel_attrs se_fchannel;
	struct nfsd4_channel_attrs se_bchannel;
	struct nfsd4_cb_sec	se_cb_sec;
	struct list_head	se_conns;
	u32			se_cb_prog;
	u32			se_cb_seq_nr;
	struct nfsd4_slot	*se_slots[];	/* forward channel slots */
};

struct nfs4_client {
	struct list_head	cl_idhash; 	/* hash by cl_clientid.id */
	struct rb_node		cl_namenode;	/* link into by-name trees */
	struct list_head	*cl_ownerstr_hashtbl;
	struct list_head	cl_openowners;
	struct idr		cl_stateids;	/* stateid lookup */
	struct list_head	cl_delegations;
	struct list_head	cl_revoked;	/* unacknowledged, revoked 4.1 state */
	struct list_head        cl_lru;         /* tail queue */
#ifdef CONFIG_NFSD_PNFS
	struct list_head	cl_lo_states;	/* outstanding layout states */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct xdr_netobj	cl_name; 	/* id generated by client */
	nfs4_verifier		cl_verifier; 	/* generated by client */
	time_t                  cl_time;        /* time of last lease renewal */
	struct sockaddr_storage	cl_addr; 	/* client ipaddress */
	bool			cl_mach_cred;	/* SP4_MACH_CRED in force */
	struct svc_cred		cl_cred; 	/* setclientid principal */
	clientid_t		cl_clientid;	/* generated by server */
	nfs4_verifier		cl_confirm;	/* generated by server */
	u32			cl_minorversion;

	/* for v4.0 and v4.1 callbacks: */
	struct nfs4_cb_conn	cl_cb_conn;
	unsigned long		cl_flags;
	struct rpc_cred		*cl_cb_cred;
	struct rpc_clnt		*cl_cb_client;
	u32			cl_cb_ident;
	int			cl_cb_state;
	struct nfsd4_callback	cl_cb_null;
	struct nfsd4_session	*cl_cb_session;

	/* for all client information that callback code might need: */
	spinlock_t		cl_lock;

	/* for nfs41 */
	struct list_head	cl_sessions;
	struct nfsd4_clid_slot	cl_cs_slot;	/* create_session slot */
	u32			cl_exchange_flags;
	/* number of rpc's in progress over an associated session: */
	atomic_t		cl_refcount;
	struct nfs4_op_map      cl_spo_must_allow;

	/* for nfs41 callbacks */
	/* We currently support a single back channel with a single slot */
	unsigned long		cl_cb_slot_busy;
	struct rpc_wait_queue	cl_cb_waitq;	/* backchannel callers may */
						/* wait here for slots */
	struct net		*net;
};

/* klp-ccp: from fs/nfsd/netns.h */
#include <net/net_namespace.h>

/* klp-ccp: from fs/nfsd/nfs4callback.c */
struct nfs4_cb_compound_hdr {
	/* args */
	u32		ident;	/* minorversion 0 only */
	u32		nops;
	__be32		*nops_p;
	u32		minorversion;
	/* res */
	int		status;
};

static void klpr_print_overflow_msg(const char *func, const struct xdr_stream *xdr)
{
	do { if ((*klpe_nfsd_debug) & 0x0010) printk("\001" "d" "NFS: %s prematurely hit the end of our receive buffer. " "Remaining buffer length is %tu words.\n",func, xdr->end - xdr->p); } while (0);
}

enum nfs_cb_opnum4 {
	OP_CB_GETATTR			= 3,
	OP_CB_RECALL			= 4,
	OP_CB_LAYOUTRECALL		= 5,
	OP_CB_NOTIFY			= 6,
	OP_CB_PUSH_DELEG		= 7,
	OP_CB_RECALL_ANY		= 8,
	OP_CB_RECALLABLE_OBJ_AVAIL	= 9,
	OP_CB_RECALL_SLOT		= 10,
	OP_CB_SEQUENCE			= 11,
	OP_CB_WANTS_CANCELLED		= 12,
	OP_CB_NOTIFY_LOCK		= 13,
	OP_CB_NOTIFY_DEVICEID		= 14,
	OP_CB_ILLEGAL			= 10044
};

static int (*klpe_decode_cb_op_status)(struct xdr_stream *xdr, enum nfs_opnum4 expected,
			       int *status);

static int klpp_decode_cb_compound4res(struct xdr_stream *xdr,
				  struct nfs4_cb_compound_hdr *hdr)
{
	u32 length;
	__be32 *p;

	p = (*klpe_xdr_inline_decode)(xdr, XDR_UNIT);
	if (unlikely(p == NULL))
		goto out_overflow;
	hdr->status = be32_to_cpup(p);
	/* Ignore the tag */
	if (klpr_xdr_stream_decode_u32(xdr, &length) < 0)
		goto out_overflow;
	if ((*klpe_xdr_inline_decode)(xdr, length) == NULL)
		goto out_overflow;
	if (klpr_xdr_stream_decode_u32(xdr, &hdr->nops) < 0)
		goto out_overflow;
	return 0;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_cb_sequence4resok(struct xdr_stream *xdr,
				    struct nfsd4_callback *cb)
{
	struct nfsd4_session *session = cb->cb_clp->cl_cb_session;
	int status = -ESERVERFAULT;
	__be32 *p;
	u32 dummy;

	/*
	 * If the server returns different values for sessionID, slotID or
	 * sequence number, the server is looney tunes.
	 */
	p = (*klpe_xdr_inline_decode)(xdr, NFS4_MAX_SESSIONID_LEN + 4 + 4 + 4 + 4);
	if (unlikely(p == NULL))
		goto out_overflow;

	if (memcmp(p, session->se_sessionid.data, NFS4_MAX_SESSIONID_LEN)) {
		do { if ((*klpe_nfsd_debug) & 0x0010) printk("\001" "d" "NFS: %s Invalid session id\n",__func__); } while (0);
		goto out;
	}
	p += XDR_QUADLEN(NFS4_MAX_SESSIONID_LEN);

	dummy = be32_to_cpup(p++);
	if (dummy != session->se_cb_seq_nr) {
		do { if ((*klpe_nfsd_debug) & 0x0010) printk("\001" "d" "NFS: %s Invalid sequence number\n",__func__); } while (0);
		goto out;
	}

	dummy = be32_to_cpup(p++);
	if (dummy != 0) {
		do { if ((*klpe_nfsd_debug) & 0x0010) printk("\001" "d" "NFS: %s Invalid slotid\n",__func__); } while (0);
		goto out;
	}

	/*
	 * FIXME: process highest slotid and target highest slotid
	 */
	status = 0;
out:
	cb->cb_seq_status = status;
	return status;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	status = -EIO;
	goto out;
}

static int klpr_decode_cb_sequence4res(struct xdr_stream *xdr,
				  struct nfsd4_callback *cb)
{
	int status;

	if (cb->cb_clp->cl_minorversion == 0)
		return 0;

	status = (*klpe_decode_cb_op_status)(xdr, OP_CB_SEQUENCE, &cb->cb_seq_status);
	if (unlikely(status || cb->cb_seq_status))
		return status;

	return klpr_decode_cb_sequence4resok(xdr, cb);
}

int klpp_nfs4_xdr_dec_cb_recall(struct rpc_rqst *rqstp,
				struct xdr_stream *xdr,
				struct nfsd4_callback *cb)
{
	struct nfs4_cb_compound_hdr hdr;
	int status;

	status = klpp_decode_cb_compound4res(xdr, &hdr);
	if (unlikely(status))
		return status;

	if (cb != NULL) {
		status = klpr_decode_cb_sequence4res(xdr, cb);
		if (unlikely(status || cb->cb_seq_status))
			return status;
	}

	return (*klpe_decode_cb_op_status)(xdr, OP_CB_RECALL, &cb->cb_status);
}

#ifdef CONFIG_NFSD_PNFS

int klpp_nfs4_xdr_dec_cb_layout(struct rpc_rqst *rqstp,
				struct xdr_stream *xdr,
				struct nfsd4_callback *cb)
{
	struct nfs4_cb_compound_hdr hdr;
	int status;

	status = klpp_decode_cb_compound4res(xdr, &hdr);
	if (unlikely(status))
		return status;

	if (cb) {
		status = klpr_decode_cb_sequence4res(xdr, cb);
		if (unlikely(status || cb->cb_seq_status))
			return status;
	}
	return (*klpe_decode_cb_op_status)(xdr, OP_CB_LAYOUTRECALL, &cb->cb_status);
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NFSD_PNFS */

int klpp_nfs4_xdr_dec_cb_notify_lock(struct rpc_rqst *rqstp,
				     struct xdr_stream *xdr,
				     struct nfsd4_callback *cb)
{
	struct nfs4_cb_compound_hdr hdr;
	int status;

	status = klpp_decode_cb_compound4res(xdr, &hdr);
	if (unlikely(status))
		return status;

	if (cb) {
		status = klpr_decode_cb_sequence4res(xdr, cb);
		if (unlikely(status || cb->cb_seq_status))
			return status;
	}
	return (*klpe_decode_cb_op_status)(xdr, OP_CB_NOTIFY_LOCK, &cb->cb_status);
}


#include "livepatch_bsc1234854.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nfsd"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "decode_cb_op_status", (void *)&klpe_decode_cb_op_status, "nfsd" },
	{ "nfsd_debug", (void *)&klpe_nfsd_debug, "sunrpc" },
	{ "xdr_inline_decode", (void *)&klpe_xdr_inline_decode, "sunrpc" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1234854_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1234854_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
