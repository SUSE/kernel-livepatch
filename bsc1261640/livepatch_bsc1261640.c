/*
 * livepatch_bsc1261640
 *
 * Fix for CVE-2026-31402, bsc#1261640
 *
 *  Copyright (c) 2026 SUSE
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


/* klp-ccp: from fs/nfsd/nfs4xdr.c */
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/namei.h>

#include <linux/utsname.h>
#include <linux/pagemap.h>

#include <linux/sunrpc/svcauth_gss.h>

/* klp-ccp: from include/linux/sunrpc/xdr.h */
#ifdef __KERNEL__

static int (*klpe_read_bytes_from_xdr_buf)(struct xdr_buf *, unsigned int, void *, unsigned int);
static int (*klpe_write_bytes_to_xdr_buf)(struct xdr_buf *, unsigned int, void *, unsigned int);

static __be32 *(*klpe_xdr_reserve_space)(struct xdr_stream *xdr, size_t nbytes);
static void (*klpe_xdr_commit_encode)(struct xdr_stream *xdr);
static void (*klpe_xdr_truncate_encode)(struct xdr_stream *xdr, size_t len);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __KERNEL__ */

/* klp-ccp: from fs/nfsd/idmap.h */
#include <linux/in.h>
#include <linux/sunrpc/svc.h>

/* klp-ccp: from fs/nfsd/state.h */
#include <linux/idr.h>
#include <linux/sunrpc/svc_xprt.h>

/* klp-ccp: from fs/nfsd/nfsfh.h */
#include <linux/sunrpc/svc.h>
#include <uapi/linux/nfsd/nfsfh.h>
#include <linux/iversion.h>

struct svc_fh {
	struct knfsd_fh		fh_handle;	/* FH data */
	int			fh_maxsize;	/* max size for fh_handle */
	struct dentry *		fh_dentry;	/* validated dentry */
	struct svc_export *	fh_export;	/* export pointer */

	bool			fh_locked;	/* inode locked by us */
	bool			fh_want_write;	/* remount protection taken */

#ifdef CONFIG_NFSD_V3
	bool			fh_post_saved;	/* post-op attrs saved */
	bool			fh_pre_saved;	/* pre-op attrs saved */

	/* Pre-op attributes saved during fh_lock */
	__u64			fh_pre_size;	/* size before operation */
	struct timespec		fh_pre_mtime;	/* mtime before oper */
	struct timespec		fh_pre_ctime;	/* ctime before oper */
	/*
	 * pre-op nfsv4 change attr: note must check IS_I_VERSION(inode)
	 *  to find out if it is valid.
	 */
	u64			fh_pre_change;

	/* Post-op attributes saved in fh_unlock */
	struct kstat		fh_post_attr;	/* full attrs after operation */
	u64			fh_post_change; /* nfsv4 change; see above */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NFSD_V3 */
};

/* klp-ccp: from fs/nfsd/state.h */
typedef struct {
	u32             cl_boot;
	u32             cl_id;
} clientid_t;

typedef struct {
	clientid_t	so_clid;
	u32		so_id;
} stateid_opaque_t;

typedef struct {
	u32                     si_generation;
	stateid_opaque_t        si_opaque;
} stateid_t;

struct nfsd4_slot {
	u32	sl_seqid;
	__be32	sl_status;
	struct svc_cred sl_cred;
	u32	sl_datalen;
	u16	sl_opcnt;

#define NFSD4_SLOT_CACHETHIS	(1 << 1)
	u8	sl_flags;
	char	sl_data[];
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

struct nfsd4_backchannel_ctl {
	u32	bc_cb_program;
	struct nfsd4_cb_sec		bc_cb_sec;
};

struct nfsd4_bind_conn_to_session {
	struct nfs4_sessionid		sessionid;
	u32				dir;
};

#define NFSD4_REPLAY_ISIZE       112 

struct nfs4_replay {
	__be32			rp_status;
	unsigned int		rp_buflen;
	char			*rp_buf;
	struct knfsd_fh		rp_openfh;
	struct mutex		rp_mutex;
	char			rp_ibuf[NFSD4_REPLAY_ISIZE];
};

struct nfs4_stateowner {
	struct list_head			so_strhash;
	struct list_head			so_stateids;
	struct nfs4_client			*so_client;
	const struct nfs4_stateowner_operations	*so_ops;
	/* after increment in nfsd4_bump_seqid, represents the next
	 * sequence id expected from the client: */
	atomic_t				so_count;
	u32					so_seqid;
	struct xdr_netobj			so_owner; /* open owner name */
	struct nfs4_replay			so_replay;
	bool					so_is_open_owner;
};

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/types.h>

#include <linux/nfs.h>
#include <linux/nfs2.h>
#include <linux/nfs3.h>
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

/* klp-ccp: from fs/nfsd/nfsd.h */
struct readdir_cd {
	__be32			err;	/* 0, nfserr, or nfserr_eof */
};

#define	nfserr_resource		cpu_to_be32(NFSERR_RESOURCE)

#define nfserr_rep_too_big		cpu_to_be32(NFS4ERR_REP_TOO_BIG)
#define nfserr_rep_too_big_to_cache	cpu_to_be32(NFS4ERR_REP_TOO_BIG_TO_CACHE)

#define COMPOUND_ERR_SLACK_SPACE	16     /* OP_SETATTR */

/* klp-ccp: from fs/nfsd/xdr4.h */
struct nfsd4_compound_state {
	struct svc_fh		current_fh;
	struct svc_fh		save_fh;
	struct nfs4_stateowner	*replay_owner;
	struct nfs4_client	*clp;
	/* For sessions DRC */
	struct nfsd4_session	*session;
	struct nfsd4_slot	*slot;
	int			data_offset;
	bool                    spo_must_allowed;
	size_t			iovlen;
	u32			minorversion;
	__be32			status;
	stateid_t	current_stateid;
	stateid_t	save_stateid;
	/* to indicate current and saved state id presents */
	u32		sid_flags;
};

static inline bool nfsd4_has_session(struct nfsd4_compound_state *cs)
{
	return cs->slot != NULL;
}

struct nfsd4_change_info {
	u32		atomic;
	bool		change_supported;
	u32		before_ctime_sec;
	u32		before_ctime_nsec;
	u64		before_change;
	u32		after_ctime_sec;
	u32		after_ctime_nsec;
	u64		after_change;
};

struct nfsd4_access {
	u32		ac_req_access;      /* request */
	u32		ac_supported;       /* response */
	u32		ac_resp_access;     /* response */
};

struct nfsd4_close {
	u32		cl_seqid;           /* request */
	stateid_t	cl_stateid;         /* request+response */
};

struct nfsd4_commit {
	u64		co_offset;          /* request */
	u32		co_count;           /* request */
	nfs4_verifier	co_verf;            /* response */
};

struct nfsd4_create {
	u32		cr_namelen;         /* request */
	char *		cr_name;            /* request */
	u32		cr_type;            /* request */
	union {                             /* request */
		struct {
			u32 datalen;
			char *data;
			struct kvec first;
		} link;   /* NF4LNK */
		struct {
			u32 specdata1;
			u32 specdata2;
		} dev;    /* NF4BLK, NF4CHR */
	} u;
	u32		cr_bmval[3];        /* request */
	struct iattr	cr_iattr;           /* request */
	int		cr_umask;           /* request */
	struct nfsd4_change_info  cr_cinfo; /* response */
	struct nfs4_acl *cr_acl;
	struct xdr_netobj cr_label;
};

struct nfsd4_delegreturn {
	stateid_t	dr_stateid;
};

struct nfsd4_getattr {
	u32		ga_bmval[3];        /* request */
	struct svc_fh	*ga_fhp;            /* response */
};

struct nfsd4_link {
	u32		li_namelen;         /* request */
	char *		li_name;            /* request */
	struct nfsd4_change_info  li_cinfo; /* response */
};

struct nfsd4_lock_denied {
	clientid_t	ld_clientid;
	struct xdr_netobj	ld_owner;
	u64             ld_start;
	u64             ld_length;
	u32             ld_type;
};

struct nfsd4_lock {
	/* request */
	u32             lk_type;
	u32             lk_reclaim;         /* boolean */
	u64             lk_offset;
	u64             lk_length;
	u32             lk_is_new;
	union {
		struct {
			u32             open_seqid;
			stateid_t       open_stateid;
			u32             lock_seqid;
			clientid_t      clientid;
			struct xdr_netobj owner;
		} new;
		struct {
			stateid_t       lock_stateid;
			u32             lock_seqid;
		} old;
	} v;

	/* response */
	union {
		struct {
			stateid_t               stateid;
		} ok;
		struct nfsd4_lock_denied        denied;
	} u;
};

struct nfsd4_lockt {
	u32				lt_type;
	clientid_t			lt_clientid;
	struct xdr_netobj		lt_owner;
	u64				lt_offset;
	u64				lt_length;
	struct nfsd4_lock_denied  	lt_denied;
};

struct nfsd4_locku {
	u32             lu_type;
	u32             lu_seqid;
	stateid_t       lu_stateid;
	u64             lu_offset;
	u64             lu_length;
};

struct nfsd4_lookup {
	u32		lo_len;             /* request */
	char *		lo_name;            /* request */
};

struct nfsd4_putfh {
	u32		pf_fhlen;           /* request */
	char		*pf_fhval;          /* request */
};

struct nfsd4_open {
	u32		op_claim_type;      /* request */
	struct xdr_netobj op_fname;	    /* request - everything but CLAIM_PREV */
	u32		op_delegate_type;   /* request - CLAIM_PREV only */
	stateid_t       op_delegate_stateid; /* request - response */
	u32		op_why_no_deleg;    /* response - DELEG_NONE_EXT only */
	u32		op_create;     	    /* request */
	u32		op_createmode;      /* request */
	int		op_umask;           /* request */
	u32		op_bmval[3];        /* request */
	struct iattr	op_iattr;           /* UNCHECKED4, GUARDED4, EXCLUSIVE4_1 */
	nfs4_verifier	op_verf __attribute__((aligned(32)));
					    /* EXCLUSIVE4 */
	clientid_t	op_clientid;        /* request */
	struct xdr_netobj op_owner;           /* request */
	u32		op_seqid;           /* request */
	u32		op_share_access;    /* request */
	u32		op_share_deny;      /* request */
	u32		op_deleg_want;      /* request */
	stateid_t	op_stateid;         /* response */
	__be32		op_xdr_error;       /* see nfsd4_open_omfg() */
	u32		op_recall;          /* recall */
	struct nfsd4_change_info  op_cinfo; /* response */
	u32		op_rflags;          /* response */
	bool		op_truncate;        /* used during processing */
	bool		op_created;         /* used during processing */
	struct nfs4_openowner *op_openowner; /* used during processing */
	struct nfs4_file *op_file;          /* used during processing */
	struct nfs4_ol_stateid *op_stp;	    /* used during processing */
	struct nfs4_clnt_odstate *op_odstate; /* used during processing */
	struct nfs4_acl *op_acl;
	struct xdr_netobj op_label;
};

struct nfsd4_open_confirm {
	stateid_t	oc_req_stateid		/* request */;
	u32		oc_seqid    		/* request */;
	stateid_t	oc_resp_stateid		/* response */;
};

struct nfsd4_open_downgrade {
	stateid_t       od_stateid;
	u32             od_seqid;
	u32             od_share_access;	/* request */
	u32		od_deleg_want;		/* request */
	u32             od_share_deny;		/* request */
};

struct nfsd4_read {
	stateid_t	rd_stateid;         /* request */
	u64		rd_offset;          /* request */
	u32		rd_length;          /* request */
	int		rd_vlen;
	struct file     *rd_filp;
	bool		rd_tmp_file;
	
	struct svc_rqst *rd_rqstp;          /* response */
	struct svc_fh * rd_fhp;             /* response */
};

struct nfsd4_readdir {
	u64		rd_cookie;          /* request */
	nfs4_verifier	rd_verf;            /* request */
	u32		rd_dircount;        /* request */
	u32		rd_maxcount;        /* request */
	u32		rd_bmval[3];        /* request */
	struct svc_rqst *rd_rqstp;          /* response */
	struct svc_fh * rd_fhp;             /* response */

	struct readdir_cd	common;
	struct xdr_stream	*xdr;
	int			cookie_offset;
};

struct nfsd4_release_lockowner {
	clientid_t        rl_clientid;
	struct xdr_netobj rl_owner;
};
struct nfsd4_readlink {
	struct svc_rqst *rl_rqstp;          /* request */
	struct svc_fh *	rl_fhp;             /* request */
};

struct nfsd4_remove {
	u32		rm_namelen;         /* request */
	char *		rm_name;            /* request */
	struct nfsd4_change_info  rm_cinfo; /* response */
};

struct nfsd4_rename {
	u32		rn_snamelen;        /* request */
	char *		rn_sname;           /* request */
	u32		rn_tnamelen;        /* request */
	char *		rn_tname;           /* request */
	struct nfsd4_change_info  rn_sinfo; /* response */
	struct nfsd4_change_info  rn_tinfo; /* response */
};

struct nfsd4_secinfo {
	u32 si_namelen;					/* request */
	char *si_name;					/* request */
	struct svc_export *si_exp;			/* response */
};

struct nfsd4_setattr {
	stateid_t	sa_stateid;         /* request */
	u32		sa_bmval[3];        /* request */
	struct iattr	sa_iattr;           /* request */
	struct nfs4_acl *sa_acl;
	struct xdr_netobj sa_label;
};

struct nfsd4_setclientid {
	nfs4_verifier	se_verf;            /* request */
	struct xdr_netobj se_name;
	u32		se_callback_prog;   /* request */
	u32		se_callback_netid_len;  /* request */
	char *		se_callback_netid_val;  /* request */
	u32		se_callback_addr_len;   /* request */
	char *		se_callback_addr_val;   /* request */
	u32		se_callback_ident;  /* request */
	clientid_t	se_clientid;        /* response */
	nfs4_verifier	se_confirm;         /* response */
};

struct nfsd4_setclientid_confirm {
	clientid_t	sc_clientid;
	nfs4_verifier	sc_confirm;
};

struct nfsd4_test_stateid {
	u32		ts_num_ids;
	struct list_head ts_stateid_list;
};

struct nfsd4_free_stateid {
	stateid_t	fr_stateid;         /* request */
};

struct nfsd4_verify {
	u32		ve_bmval[3];        /* request */
	u32		ve_attrlen;         /* request */
	char *		ve_attrval;         /* request */
};

struct nfsd4_write {
	stateid_t	wr_stateid;         /* request */
	u64		wr_offset;          /* request */
	u32		wr_stable_how;      /* request */
	u32		wr_buflen;          /* request */
	struct kvec	wr_head;
	struct page **	wr_pagelist;        /* request */

	u32		wr_bytes_written;   /* response */
	u32		wr_how_written;     /* response */
	nfs4_verifier	wr_verifier;        /* response */
};

struct nfsd4_exchange_id {
	nfs4_verifier	verifier;
	struct xdr_netobj clname;
	u32		flags;
	clientid_t	clientid;
	u32		seqid;
	int		spa_how;
	u32             spo_must_enforce[3];
	u32             spo_must_allow[3];
};

struct nfsd4_sequence {
	struct nfs4_sessionid	sessionid;		/* request/response */
	u32			seqid;			/* request/response */
	u32			slotid;			/* request/response */
	u32			maxslots;		/* request/response */
	u32			cachethis;		/* request */
#if 0
#error "klp-ccp: non-taken branch"
#endif /* not yet */
	u32			status_flags;		/* response */
};

struct nfsd4_destroy_session {
	struct nfs4_sessionid	sessionid;
};

struct nfsd4_reclaim_complete {
	u32 rca_one_fs;
};

struct nfsd4_deviceid {
	u64			fsid_idx;
	u32			generation;
	u32			pad;
};

struct nfsd4_layout_seg {
	u32			iomode;
	u64			offset;
	u64			length;
};

struct nfsd4_getdeviceinfo {
	struct nfsd4_deviceid	gd_devid;	/* request */
	u32			gd_layout_type;	/* request */
	u32			gd_maxcount;	/* request */
	u32			gd_notify_types;/* request - response */
	void			*gd_device;	/* response */
};

struct nfsd4_layoutget {
	u64			lg_minlength;	/* request */
	u32			lg_signal;	/* request */
	u32			lg_layout_type;	/* request */
	u32			lg_maxcount;	/* request */
	stateid_t		lg_sid;		/* request/response */
	struct nfsd4_layout_seg	lg_seg;		/* request/response */
	void			*lg_content;	/* response */
};

struct nfsd4_layoutcommit {
	stateid_t		lc_sid;		/* request */
	struct nfsd4_layout_seg	lc_seg;		/* request */
	u32			lc_reclaim;	/* request */
	u32			lc_newoffset;	/* request */
	u64			lc_last_wr;	/* request */
	struct timespec		lc_mtime;	/* request */
	u32			lc_layout_type;	/* request */
	u32			lc_up_len;	/* layout length */
	void			*lc_up_layout;	/* decoded by callback */
	u32			lc_size_chg;	/* boolean for response */
	u64			lc_newsize;	/* response */
};

struct nfsd4_layoutreturn {
	u32			lr_return_type;	/* request */
	u32			lr_layout_type;	/* request */
	struct nfsd4_layout_seg	lr_seg;		/* request */
	u32			lr_reclaim;	/* request */
	u32			lrf_body_len;	/* request */
	void			*lrf_body;	/* request */
	stateid_t		lr_sid;		/* request/response */
	u32			lrs_present;	/* response */
};

struct nfsd4_fallocate {
	/* request */
	stateid_t	falloc_stateid;
	loff_t		falloc_offset;
	u64		falloc_length;
};

struct nfsd4_clone {
	/* request */
	stateid_t	cl_src_stateid;
	stateid_t	cl_dst_stateid;
	u64		cl_src_pos;
	u64		cl_dst_pos;
	u64		cl_count;
};

struct nfsd42_write_res {
	u64			wr_bytes_written;
	u32			wr_stable_how;
	nfs4_verifier		wr_verifier;
};

struct nfsd4_copy {
	/* request */
	stateid_t	cp_src_stateid;
	stateid_t	cp_dst_stateid;
	u64		cp_src_pos;
	u64		cp_dst_pos;
	u64		cp_count;

	/* both */
	bool		cp_consecutive;
	bool		cp_synchronous;

	/* response */
	struct nfsd42_write_res	cp_res;
};

struct nfsd4_seek {
	/* request */
	stateid_t	seek_stateid;
	loff_t		seek_offset;
	u32		seek_whence;

	/* response */
	u32		seek_eof;
	loff_t		seek_pos;
};

struct nfsd4_op {
	int					opnum;
	__be32					status;
	union {
		struct nfsd4_access		access;
		struct nfsd4_close		close;
		struct nfsd4_commit		commit;
		struct nfsd4_create		create;
		struct nfsd4_delegreturn	delegreturn;
		struct nfsd4_getattr		getattr;
		struct svc_fh *			getfh;
		struct nfsd4_link		link;
		struct nfsd4_lock		lock;
		struct nfsd4_lockt		lockt;
		struct nfsd4_locku		locku;
		struct nfsd4_lookup		lookup;
		struct nfsd4_verify		nverify;
		struct nfsd4_open		open;
		struct nfsd4_open_confirm	open_confirm;
		struct nfsd4_open_downgrade	open_downgrade;
		struct nfsd4_putfh		putfh;
		struct nfsd4_read		read;
		struct nfsd4_readdir		readdir;
		struct nfsd4_readlink		readlink;
		struct nfsd4_remove		remove;
		struct nfsd4_rename		rename;
		clientid_t			renew;
		struct nfsd4_secinfo		secinfo;
		struct nfsd4_setattr		setattr;
		struct nfsd4_setclientid	setclientid;
		struct nfsd4_setclientid_confirm setclientid_confirm;
		struct nfsd4_verify		verify;
		struct nfsd4_write		write;
		struct nfsd4_release_lockowner	release_lockowner;

		/* NFSv4.1 */
		struct nfsd4_exchange_id	exchange_id;
		struct nfsd4_backchannel_ctl	backchannel_ctl;
		struct nfsd4_bind_conn_to_session bind_conn_to_session;
		struct nfsd4_create_session	create_session;
		struct nfsd4_destroy_session	destroy_session;
		struct nfsd4_sequence		sequence;
		struct nfsd4_reclaim_complete	reclaim_complete;
		struct nfsd4_test_stateid	test_stateid;
		struct nfsd4_free_stateid	free_stateid;
		struct nfsd4_getdeviceinfo	getdeviceinfo;
		struct nfsd4_layoutget		layoutget;
		struct nfsd4_layoutcommit	layoutcommit;
		struct nfsd4_layoutreturn	layoutreturn;

		/* NFSv4.2 */
		struct nfsd4_fallocate		allocate;
		struct nfsd4_fallocate		deallocate;
		struct nfsd4_clone		clone;
		struct nfsd4_copy		copy;
		struct nfsd4_seek		seek;
	} u;
	struct nfs4_replay *			replay;
};

struct nfsd4_compoundargs {
	/* scratch variables for XDR decode */
	__be32 *			p;
	__be32 *			end;
	struct page **			pagelist;
	int				pagelen;
	__be32				tmp[8];
	__be32 *			tmpp;
	struct svcxdr_tmpbuf		*to_free;

	struct svc_rqst			*rqstp;

	u32				taglen;
	char *				tag;
	u32				minorversion;
	u32				opcnt;
	struct nfsd4_op			*ops;
	struct nfsd4_op			iops[8];
	int				cachetype;
};

struct nfsd4_compoundres {
	/* scratch variables for XDR encode */
	struct xdr_stream		xdr;
	struct svc_rqst *		rqstp;

	u32				taglen;
	char *				tag;
	u32				opcnt;
	__be32 *			tagp; /* tag, opcount encode location */
	struct nfsd4_compound_state	cstate;
};

static inline bool nfsd4_last_compound_op(struct svc_rqst *rqstp)
{
	struct nfsd4_compoundres *resp = rqstp->rq_resp;
	struct nfsd4_compoundargs *argp = rqstp->rq_argp;

	return argp->opcnt == resp->opcnt;
}

static void (*klpe_warn_on_nonidempotent_op)(struct nfsd4_op *op);

static __be32 (*klpe_nfsd4_check_resp_size)(struct nfsd4_compoundres *, u32);

/* klp-ccp: from fs/nfsd/cache.h */
#include <linux/sunrpc/svc.h>

/* klp-ccp: from fs/nfsd/netns.h */
#include <net/net_namespace.h>

/* klp-ccp: from fs/nfsd/pnfs.h */
#ifdef CONFIG_NFSD_V4

#include <linux/nfsd/export.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NFSD_V4 */

/* klp-ccp: from fs/nfsd/nfs4xdr.c */
typedef __be32(* nfsd4_enc)(struct nfsd4_compoundres *, __be32, void *);

static nfsd4_enc (*klpe_nfsd4_enc_ops)[72];

void klpp_nfsd4_encode_operation(struct nfsd4_compoundres *resp, struct nfsd4_op *op)
{
	struct xdr_stream *xdr = &resp->xdr;
	struct nfs4_stateowner *so = resp->cstate.replay_owner;
	struct svc_rqst *rqstp = resp->rqstp;
	int post_err_offset;
	nfsd4_enc encoder;
	__be32 *p;

	p = (*klpe_xdr_reserve_space)(xdr, 8);
	if (!p) {
		WARN_ON_ONCE(1);
		return;
	}
	*p++ = cpu_to_be32(op->opnum);
	post_err_offset = xdr->buf->len;

	if (op->opnum == OP_ILLEGAL)
		goto status;
	BUG_ON(op->opnum < 0 || op->opnum >= ARRAY_SIZE((*klpe_nfsd4_enc_ops)) ||
	       !(*klpe_nfsd4_enc_ops)[op->opnum]);
	encoder = (*klpe_nfsd4_enc_ops)[op->opnum];
	op->status = encoder(resp, op->status, &op->u);
	(*klpe_xdr_commit_encode)(xdr);

	/* nfsd4_check_resp_size guarantees enough room for error status */
	if (!op->status) {
		int space_needed = 0;
		if (!nfsd4_last_compound_op(rqstp))
			space_needed = COMPOUND_ERR_SLACK_SPACE;
		op->status = (*klpe_nfsd4_check_resp_size)(resp, space_needed);
	}
	if (op->status == nfserr_resource && nfsd4_has_session(&resp->cstate)) {
		struct nfsd4_slot *slot = resp->cstate.slot;

		if (slot->sl_flags & NFSD4_SLOT_CACHETHIS)
			op->status = nfserr_rep_too_big_to_cache;
		else
			op->status = nfserr_rep_too_big;
	}
	if (op->status == nfserr_resource ||
	    op->status == nfserr_rep_too_big ||
	    op->status == nfserr_rep_too_big_to_cache) {
		/*
		 * The operation may have already been encoded or
		 * partially encoded.  No op returns anything additional
		 * in the case of one of these three errors, so we can
		 * just truncate back to after the status.  But it's a
		 * bug if we had to do this on a non-idempotent op:
		 */
		(*klpe_warn_on_nonidempotent_op)(op);
		(*klpe_xdr_truncate_encode)(xdr, post_err_offset);
	}
	if (so) {
		int len = xdr->buf->len - post_err_offset;

		so->so_replay.rp_status = op->status;
		if (len <= NFSD4_REPLAY_ISIZE) {
			so->so_replay.rp_buflen = len;
			(*klpe_read_bytes_from_xdr_buf)(xdr->buf, post_err_offset,
						so->so_replay.rp_buf, len);
		} else {
			so->so_replay.rp_buflen = 0;
		}
	}
status:
	/* Note that op->status is already in network byte order: */
	(*klpe_write_bytes_to_xdr_buf)(xdr->buf, post_err_offset - 4, &op->status, 4);
}


#include "livepatch_bsc1261640.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nfsd"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfsd4_check_resp_size", (void *)&klpe_nfsd4_check_resp_size,
	  "nfsd" },
	{ "nfsd4_enc_ops", (void *)&klpe_nfsd4_enc_ops, "nfsd" },
	{ "warn_on_nonidempotent_op", (void *)&klpe_warn_on_nonidempotent_op,
	  "nfsd" },
	{ "read_bytes_from_xdr_buf", (void *)&klpe_read_bytes_from_xdr_buf,
	  "sunrpc" },
	{ "write_bytes_to_xdr_buf", (void *)&klpe_write_bytes_to_xdr_buf,
	  "sunrpc" },
	{ "xdr_commit_encode", (void *)&klpe_xdr_commit_encode, "sunrpc" },
	{ "xdr_reserve_space", (void *)&klpe_xdr_reserve_space, "sunrpc" },
	{ "xdr_truncate_encode", (void *)&klpe_xdr_truncate_encode, "sunrpc" },
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

int livepatch_bsc1261640_init(void)
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

void livepatch_bsc1261640_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
