/*
 * livepatch_bsc1272136
 *
 * Fix for CVE-2026-63795, bsc#1272136
 *
 *  Copyright (c) 2026 SUSE
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

#include "livepatch_bsc1272136.h"

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <net/9p/9p.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
/* klp-ccp: from include/net/9p/client.h */
#include <linux/utsname.h>
#include <linux/idr.h>
#include <linux/tracepoint-defs.h>

enum p9_trans_status {
	Connected,
	BeginDisconnect,
	Disconnected,
	Hung,
};

struct p9_req_t {
	int status;
	int t_err;
	refcount_t refcount;
	wait_queue_head_t wq;
	struct p9_fcall tc;
	struct p9_fcall rc;
	struct list_head req_list;
};

struct p9_client {
	spinlock_t lock;
	unsigned int msize;
	unsigned char proto_version;
	struct p9_trans_module *trans_mod;
	enum p9_trans_status status;
	void *trans;
	struct kmem_cache *fcall_cache;

	union {
		struct {
			int rfd;
			int wfd;
		} fd;
		struct {
			u16 port;
			bool privport;

		} tcp;
	} trans_opts;

	struct idr fids;
	struct idr reqs;

	char name[__NEW_UTS_LEN + 1];
};

struct p9_fid {
	struct p9_client *clnt;
	u32 fid;
	refcount_t count;
	int mode;
	struct p9_qid qid;
	u32 iounit;
	kuid_t uid;

	void *rdir;

	struct hlist_node dlist;	/* list of all fids attached to a dentry */
	struct hlist_node ilist;
};
int p9_client_clunk(struct p9_fid *fid);

int p9_req_put(struct p9_client *c, struct p9_req_t *r);

DECLARE_TRACEPOINT(9p_fid_ref);

void do_trace_9p_fid_put(struct p9_fid *fid);

# define klpr_tracepoint_enabled(tp) \
	static_key_enabled(&(__tracepoint_##tp).key)

static inline int p9_fid_put(struct p9_fid *fid)
{
	if (!fid || IS_ERR(fid))
		return 0;

	if (klpr_tracepoint_enabled(9p_fid_ref))
		do_trace_9p_fid_put(fid);

	if (!refcount_dec_and_test(&fid->count))
		return 0;

	return p9_client_clunk(fid);
}


#include "../klp_trace.h"
KLPR_TRACE_EVENT(9pnet,
            9p_protocol_dump,
	    TP_PROTO(struct p9_client *clnt, struct p9_fcall *pdu),
	    TP_ARGS(clnt, pdu))

/* klp-ccp: from net/9p/protocol.h */
int p9pdu_readf(struct p9_fcall *pdu, int proto_version, const char *fmt, ...);

/* klp-ccp: from net/9p/client.c */
#include <net/9p/transport.h>

/* klp-ccp: from net/9p/protocol.h */
int p9pdu_readf(struct p9_fcall *pdu, int proto_version, const char *fmt, ...);

/* klp-ccp: from net/9p/client.c */
int p9_req_put(struct p9_client *c, struct p9_req_t *r);

extern typeof(p9_req_put) p9_req_put;

extern struct p9_req_t *
p9_client_rpc(struct p9_client *c, int8_t type, const char *fmt, ...);

struct p9_req_t *
p9_client_rpc(struct p9_client *c, int8_t type, const char *fmt, ...);

extern struct p9_fid *p9_fid_create(struct p9_client *clnt);

extern void p9_fid_destroy(struct p9_fid *fid);

extern typeof(__tracepoint_9p_fid_ref) __tracepoint_9p_fid_ref;

void do_trace_9p_fid_put(struct p9_fid *fid);

extern typeof(do_trace_9p_fid_put) do_trace_9p_fid_put;

struct p9_fid *klpp_p9_client_walk(struct p9_fid *oldfid, uint16_t nwname,
			      const unsigned char * const *wnames, int clone)
{
	int err;
	struct p9_client *clnt;
	struct p9_fid *fid;
	struct p9_qid *wqids;
	struct p9_req_t *req;
	u16 nwqids, count;

	err = 0;
	wqids = NULL;
	clnt = oldfid->clnt;
	if (clone) {
		fid = p9_fid_create(clnt);
		if (!fid) {
			err = -ENOMEM;
			goto error;
		}

		fid->uid = oldfid->uid;
	} else {
		fid = oldfid;
	}

	p9_debug(P9_DEBUG_9P, ">>> TWALK fids %d,%d nwname %ud wname[0] %s\n",
		 oldfid->fid, fid->fid, nwname, wnames ? wnames[0] : NULL);
	req = p9_client_rpc(clnt, P9_TWALK, "ddT", oldfid->fid, fid->fid,
			    nwname, wnames);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(&req->rc, clnt->proto_version, "R", &nwqids, &wqids);
	if (err) {
		klpr_trace_9p_protocol_dump(clnt, &req->rc);
		p9_req_put(clnt, req);
		goto clunk_fid;
	}
	p9_req_put(clnt, req);

	p9_debug(P9_DEBUG_9P, "<<< RWALK nwqid %d:\n", nwqids);

	if (nwqids != nwname) {
		err = -ENOENT;
		goto clunk_fid;
	}

	for (count = 0; count < nwqids; count++)
		p9_debug(P9_DEBUG_9P, "<<<     [%d] %x.%llx.%x\n",
			 count, wqids[count].type,
			 wqids[count].path,
			 wqids[count].version);

	if (nwname)
		memmove(&fid->qid, &wqids[nwqids - 1], sizeof(struct p9_qid));
	else
		memmove(&fid->qid, &oldfid->qid, sizeof(struct p9_qid));

	kfree(wqids);
	return fid;

clunk_fid:
	kfree(wqids);
	if (fid != oldfid)
		p9_fid_put(fid);
	fid = NULL;

error:
	if (fid && fid != oldfid)
		p9_fid_destroy(fid);

	return ERR_PTR(err);
}
int p9_client_clunk(struct p9_fid *fid);

extern typeof(p9_client_clunk) p9_client_clunk;


#include <linux/livepatch.h>

extern typeof(__tracepoint_9p_fid_ref) __tracepoint_9p_fid_ref
	 KLP_RELOC_SYMBOL(9pnet, 9pnet, __tracepoint_9p_fid_ref);
extern typeof(do_trace_9p_fid_put) do_trace_9p_fid_put
	 KLP_RELOC_SYMBOL(9pnet, 9pnet, do_trace_9p_fid_put);
extern typeof(p9_client_clunk) p9_client_clunk
	 KLP_RELOC_SYMBOL(9pnet, 9pnet, p9_client_clunk);
extern typeof(p9_client_rpc) p9_client_rpc
	 KLP_RELOC_SYMBOL(9pnet, 9pnet, p9_client_rpc);
extern typeof(p9_fid_create) p9_fid_create
	 KLP_RELOC_SYMBOL(9pnet, 9pnet, p9_fid_create);
extern typeof(p9_fid_destroy) p9_fid_destroy
	 KLP_RELOC_SYMBOL(9pnet, 9pnet, p9_fid_destroy);
extern typeof(p9_req_put) p9_req_put KLP_RELOC_SYMBOL(9pnet, 9pnet, p9_req_put);
extern typeof(p9pdu_readf) p9pdu_readf
	 KLP_RELOC_SYMBOL(9pnet, 9pnet, p9pdu_readf);
