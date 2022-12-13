/*
 * bsc1205130_fs_nfsd_nfs4proc
 *
 * Fix for CVE-2022-43945, bsc#1205130
 *
 *  Copyright (c) 2022 SUSE
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

/* klp-ccp: from fs/nfsd/nfs4proc.c */
#include <linux/fs_struct.h>
#include <linux/slab.h>
/* klp-ccp: from fs/nfsd/idmap.h */
#include <linux/in.h>
#include <linux/sunrpc/svc.h>

/* klp-ccp: from include/linux/sunrpc/debug.h */
static unsigned int (*klpe_nfsd_debug);

/* klp-ccp: from include/linux/sunrpc/xdr.h */
static __be32 *(*klpe_xdr_reserve_space)(struct xdr_stream *xdr, size_t nbytes);

/* klp-ccp: from include/linux/sunrpc/svc.h */
static u32 (*klpe_svc_max_payload)(const struct svc_rqst *rqstp);

/* klp-ccp: from include/uapi/linux/nfs_idmap.h */
#define IDMAP_NAMESZ  128

/* klp-ccp: from fs/nfsd/cache.h */
#include <linux/sunrpc/svc.h>
/* klp-ccp: from fs/nfsd/state.h */
#include <linux/idr.h>
/* klp-ccp: from fs/nfsd/nfsfh.h */
#include <linux/sunrpc/svc.h>
#include <uapi/linux/nfsd/nfsfh.h>

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

static void	(*klpe_fh_put)(struct svc_fh *);

static __inline__ struct svc_fh *
fh_init(struct svc_fh *fhp, int maxsize)
{
	memset(fhp, 0, sizeof(*fhp));
	fhp->fh_maxsize = maxsize;
	return fhp;
}

static inline void
fh_clear_wcc(struct svc_fh *fhp)
{
	fhp->fh_post_saved = false;
	fhp->fh_pre_saved = false;
}

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

struct nfsd_stats {
	unsigned int	rchits;		/* repcache hits */
	unsigned int	rcmisses;	/* repcache hits */
	unsigned int	rcnocache;	/* uncached reqs */
	unsigned int	fh_stale;	/* FH stale error */
	unsigned int	fh_lookup;	/* dentry cached */
	unsigned int	fh_anon;	/* anon file dentry returned */
	unsigned int	fh_nocache_dir;	/* filehandle not found in dcache */
	unsigned int	fh_nocache_nondir;	/* filehandle not found in dcache */
	unsigned int	io_read;	/* bytes returned to read requests */
	unsigned int	io_write;	/* bytes passed in write requests */
	unsigned int	th_cnt;		/* number of available threads */
	unsigned int	th_usage[10];	/* number of ticks during which n perdeciles
					 * of available threads were in use */
	unsigned int	th_fullcnt;	/* number of times last free thread was used */
	unsigned int	ra_size;	/* size of ra cache */
	unsigned int	ra_depth[11];	/* number of times ra entry was found that deep
					 * in the cache (10percentiles). [10] = not found */
#ifdef CONFIG_NFSD_V4
	unsigned int	nfs4_opcount[LAST_NFS4_OP + 1];	/* count of individual nfsv4 operations */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

static struct nfsd_stats	(*klpe_nfsdstats);

/* klp-ccp: from fs/nfsd/export.h */
#include <linux/sunrpc/cache.h>
#include <uapi/linux/nfsd/export.h>
#include <linux/nfs4.h>

struct nfsd4_fs_locations {
	uint32_t locations_count;
	struct nfsd4_fs_location *locations;
/* If we're not actually serving this data ourselves (only providing a
 * list of replicas that do serve it) then we set "migrated": */
	int migrated;
};

#define MAX_SECINFO_LIST	8

struct exp_flavor_info {
	u32	pseudoflavor;
	u32	flags;
};

struct svc_export {
	struct cache_head	h;
	struct auth_domain *	ex_client;
	int			ex_flags;
	struct path		ex_path;
	kuid_t			ex_anon_uid;
	kgid_t			ex_anon_gid;
	int			ex_fsid;
	unsigned char *		ex_uuid; /* 16 byte fsid */
	struct nfsd4_fs_locations ex_fslocs;
	uint32_t		ex_nflavors;
	struct exp_flavor_info	ex_flavors[MAX_SECINFO_LIST];
	u32			ex_layout_types;
	struct nfsd4_deviceid_map *ex_devid_map;
	struct cache_detail	*cd;
};

static __be32 (*klpe_check_nfsd_access)(struct svc_export *exp, struct svc_rqst *rqstp);

/* klp-ccp: from fs/nfsd/nfsd.h */
struct readdir_cd {
	__be32			err;	/* 0, nfserr, or nfserr_eof */
};

enum vers_op {NFSD_SET, NFSD_CLEAR, NFSD_TEST, NFSD_AVAIL };

static int (*klpe_nfsd_minorversion)(u32 minorversion, enum vers_op change);

#define	nfs_ok			cpu_to_be32(NFS_OK)

#define	nfserr_notsupp		cpu_to_be32(NFSERR_NOTSUPP)

#define	nfserr_moved		cpu_to_be32(NFSERR_MOVED)
#define	nfserr_nofilehandle	cpu_to_be32(NFSERR_NOFILEHANDLE)
#define	nfserr_minor_vers_mismatch	cpu_to_be32(NFSERR_MINOR_VERS_MISMATCH)

#define	nfserr_op_illegal	cpu_to_be32(NFSERR_OP_ILLEGAL)

#define nfserr_op_not_in_session	cpu_to_be32(NFS4ERR_OP_NOT_IN_SESSION)

#define nfserr_not_only_op		cpu_to_be32(NFS4ERR_NOT_ONLY_OP)

#define	nfserr_replay_me	cpu_to_be32(11001)

#define	nfserr_replay_cache	cpu_to_be32(11002)

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

static __be32 (*klpe_nfsd4_check_resp_size)(struct nfsd4_compoundres *, u32);
static void (*klpe_nfsd4_encode_operation)(struct nfsd4_compoundres *, struct nfsd4_op *);
static void (*klpe_nfsd4_encode_replay)(struct xdr_stream *xdr, struct nfsd4_op *op);

static void (*klpe_nfsd4_cstate_clear_replay)(struct nfsd4_compound_state *cstate);

/* klp-ccp: from fs/nfsd/current_stateid.h */
static void (*klpe_clear_current_stateid)(struct nfsd4_compound_state *cstate);

/* klp-ccp: from fs/nfsd/netns.h */
#include <net/net_namespace.h>

/* klp-ccp: from fs/nfsd/pnfs.h */
#include <linux/nfsd/export.h>

/* klp-ccp: from fs/nfsd/trace.h */
#include <trace/define_trace.h>

/* klp-ccp: from fs/nfsd/nfs4proc.c */
static __be32
(*klpe_nfsd4_open)(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	   struct nfsd4_open *open);

static __be32 klpr_nfsd4_open_omfg(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate, struct nfsd4_op *op)
{
	struct nfsd4_open *open = (struct nfsd4_open *)&op->u;

	if (!seqid_mutating_err(ntohl(op->status)))
		return op->status;
	if (nfsd4_has_session(cstate))
		return op->status;
	open->op_xdr_error = op->status;
	return (*klpe_nfsd4_open)(rqstp, cstate, open);
}

static inline void klpr_nfsd4_increment_op_stats(u32 opnum)
{
	if (opnum >= FIRST_NFS4_OP && opnum <= LAST_NFS4_OP)
		(*klpe_nfsdstats).nfs4_opcount[opnum]++;
}

typedef __be32(*nfsd4op_func)(struct svc_rqst *, struct nfsd4_compound_state *,
			      void *);
typedef u32(*nfsd4op_rsize)(struct svc_rqst *, struct nfsd4_op *op);
typedef void(*stateid_setter)(struct nfsd4_compound_state *, void *);
typedef void(*stateid_getter)(struct nfsd4_compound_state *, void *);

enum nfsd4_op_flags {
	ALLOWED_WITHOUT_FH = 1 << 0,	/* No current filehandle required */
	ALLOWED_ON_ABSENT_FS = 1 << 1,	/* ops processed on absent fs */
	ALLOWED_AS_FIRST_OP = 1 << 2,	/* ops reqired first in compound */
	/* For rfc 5661 section 2.6.3.1.1: */
	OP_HANDLES_WRONGSEC = 1 << 3,
	OP_IS_PUTFH_LIKE = 1 << 4,
	/*
	 * These are the ops whose result size we estimate before
	 * encoding, to avoid performing an op then not being able to
	 * respond or cache a response.  This includes writes and setattrs
	 * as well as the operations usually called "nonidempotent":
	 */
	OP_MODIFIES_SOMETHING = 1 << 5,
	/*
	 * Cache compounds containing these ops in the xid-based drc:
	 * We use the DRC for compounds containing non-idempotent
	 * operations, *except* those that are 4.1-specific (since
	 * sessions provide their own EOS), and except for stateful
	 * operations other than setclientid and setclientid_confirm
	 * (since sequence numbers provide EOS for open, lock, etc in
	 * the v4.0 case).
	 */
	OP_CACHEME = 1 << 6,
	/*
	 * These are ops which clear current state id.
	 */
	OP_CLEAR_STATEID = 1 << 7,
};

struct nfsd4_operation {
	nfsd4op_func op_func;
	u32 op_flags;
	char *op_name;
	/* Try to get response size before operation */
	nfsd4op_rsize op_rsize_bop;
	stateid_getter op_get_currentstateid;
	stateid_setter op_set_currentstateid;
};

static struct nfsd4_operation (*klpe_nfsd4_ops)[72];

static const char *klpr_nfsd4_op_name(unsigned opnum);

static __be32 klpr_nfs41_check_op_ordering(struct nfsd4_compoundargs *args)
{
	struct nfsd4_op *op = &args->ops[0];

	/* These ordering requirements don't apply to NFSv4.0: */
	if (args->minorversion == 0)
		return nfs_ok;
	/* This is weird, but OK, not our problem: */
	if (args->opcnt == 0)
		return nfs_ok;
	if (op->status == nfserr_op_illegal)
		return nfs_ok;
	if (!((*klpe_nfsd4_ops)[op->opnum].op_flags & ALLOWED_AS_FIRST_OP))
		return nfserr_op_not_in_session;
	if (op->opnum == OP_SEQUENCE)
		return nfs_ok;
	if (args->opcnt != 1)
		return nfserr_not_only_op;
	return nfs_ok;
}

static inline struct nfsd4_operation *klpr_OPDESC(struct nfsd4_op *op)
{
	return &(*klpe_nfsd4_ops)[op->opnum];
}

static bool klpr_need_wrongsec_check(struct svc_rqst *rqstp)
{
	struct nfsd4_compoundres *resp = rqstp->rq_resp;
	struct nfsd4_compoundargs *argp = rqstp->rq_argp;
	struct nfsd4_op *this = &argp->ops[resp->opcnt - 1];
	struct nfsd4_op *next = &argp->ops[resp->opcnt];
	struct nfsd4_operation *thisd;
	struct nfsd4_operation *nextd;

	thisd = klpr_OPDESC(this);
	/*
	 * Most ops check wronsec on our own; only the putfh-like ops
	 * have special rules.
	 */
	if (!(thisd->op_flags & OP_IS_PUTFH_LIKE))
		return false;
	/*
	 * rfc 5661 2.6.3.1.1.6: don't bother erroring out a
	 * put-filehandle operation if we're not going to use the
	 * result:
	 */
	if (argp->opcnt == resp->opcnt)
		return false;
	if (next->opnum == OP_ILLEGAL)
		return false;
	nextd = klpr_OPDESC(next);
	/*
	 * Rest of 2.6.3.1.1: certain operations will return WRONGSEC
	 * errors themselves as necessary; others should check for them
	 * now:
	 */
	return !(nextd->op_flags & OP_HANDLES_WRONGSEC);
}

static void svcxdr_init_encode(struct svc_rqst *rqstp,
			       struct nfsd4_compoundres *resp)
{
	struct xdr_stream *xdr = &resp->xdr;
	struct xdr_buf *buf = &rqstp->rq_res;
	struct kvec *head = buf->head;

	xdr->buf = buf;
	xdr->iov = head;
	xdr->p   = head->iov_base + head->iov_len;
	xdr->end = head->iov_base + PAGE_SIZE - rqstp->rq_auth_slack;
	/* Tail and page_len should be zero at this point: */
	buf->len = buf->head[0].iov_len;
	xdr->scratch.iov_len = 0;
	xdr->page_ptr = buf->pages - 1;
	buf->buflen = PAGE_SIZE * (1 + rqstp->rq_page_end - buf->pages)
		- rqstp->rq_auth_slack;
}

static int rsize_bop(nfsd4op_rsize op_rsize_bop,
		struct svc_rqst *rqstp, struct nfsd4_op *op);

#include "common.h"

__be32 klpp_nfsd4_proc_compound(struct svc_rqst *rqstp,
		    struct nfsd4_compoundargs *args,
		    struct nfsd4_compoundres *resp)
{
	struct nfsd4_op	*op;
	struct nfsd4_operation *opdesc;
	struct nfsd4_compound_state *cstate = &resp->cstate;
	struct svc_fh *current_fh = &cstate->current_fh;
	struct svc_fh *save_fh = &cstate->save_fh;
	__be32		status;

	svcxdr_init_encode(rqstp, resp);
	resp->tagp = resp->xdr.p;
	/* reserve space for: taglen, tag, and opcnt */
	(*klpe_xdr_reserve_space)(&resp->xdr, 8 + args->taglen);
	resp->taglen = args->taglen;
	resp->tag = args->tag;
	resp->rqstp = rqstp;
	cstate->minorversion = args->minorversion;
	fh_init(current_fh, NFS4_FHSIZE);
	fh_init(save_fh, NFS4_FHSIZE);
	/*
	 * Don't use the deferral mechanism for NFSv4; compounds make it
	 * too hard to avoid non-idempotency problems.
	 */
	clear_bit(RQ_USEDEFERRAL, &rqstp->rq_flags);

	/*
	 * According to RFC3010, this takes precedence over all other errors.
	 */
	status = nfserr_minor_vers_mismatch;
	if ((*klpe_nfsd_minorversion)(args->minorversion, NFSD_TEST) <= 0)
		goto out;

	status = klpr_nfs41_check_op_ordering(args);
	if (status) {
		op = &args->ops[0];
		op->status = status;
		resp->opcnt = 1;
		goto encode_op;
	}

	while (!status && resp->opcnt < args->opcnt) {
		op = &args->ops[resp->opcnt++];

		klpr_dprintk("nfsv4 compound op #%d/%d: %d (%s)\n",
				resp->opcnt, args->opcnt,
				op->opnum,
				klpr_nfsd4_op_name(op->opnum));
		/*
		 * The XDR decode routines may have pre-set op->status;
		 * for example, if there is a miscellaneous XDR error
		 * it will be set to nfserr_bad_xdr.
		 */
		if (op->status) {
			if (op->opnum == OP_OPEN)
				op->status = klpr_nfsd4_open_omfg(rqstp, cstate, op);
			goto encode_op;
		}

		opdesc = klpr_OPDESC(op);

		if (!current_fh->fh_dentry) {
			if (!(opdesc->op_flags & ALLOWED_WITHOUT_FH)) {
				op->status = nfserr_nofilehandle;
				goto encode_op;
			}
		} else if (current_fh->fh_export->ex_fslocs.migrated &&
			  !(opdesc->op_flags & ALLOWED_ON_ABSENT_FS)) {
			op->status = nfserr_moved;
			goto encode_op;
		}

		fh_clear_wcc(current_fh);

		/* If op is non-idempotent */
		if (opdesc->op_flags & OP_MODIFIES_SOMETHING) {
			/*
			 * Don't execute this op if we couldn't encode a
			 * succesful reply:
			 */
			u32 plen = rsize_bop(opdesc->op_rsize_bop, rqstp, op);
			/*
			 * Plus if there's another operation, make sure
			 * we'll have space to at least encode an error:
			 */
			if (resp->opcnt < args->opcnt)
				plen += COMPOUND_ERR_SLACK_SPACE;
			op->status = (*klpe_nfsd4_check_resp_size)(resp, plen);
		}

		if (op->status)
			goto encode_op;

		if (opdesc->op_get_currentstateid)
			opdesc->op_get_currentstateid(cstate, &op->u);
		op->status = opdesc->op_func(rqstp, cstate, &op->u);

		/* Only from SEQUENCE */
		if (cstate->status == nfserr_replay_cache) {
			klpr_dprintk("%s NFS4.1 replay from cache\n", __func__);
			status = op->status;
			goto out;
		}
		if (!op->status) {
			if (opdesc->op_set_currentstateid)
				opdesc->op_set_currentstateid(cstate, &op->u);

			if (opdesc->op_flags & OP_CLEAR_STATEID)
				(*klpe_clear_current_stateid)(cstate);

			if (klpr_need_wrongsec_check(rqstp))
				op->status = (*klpe_check_nfsd_access)(current_fh->fh_export, rqstp);
		}
encode_op:
		if (op->status == nfserr_replay_me) {
			op->replay = &cstate->replay_owner->so_replay;
			(*klpe_nfsd4_encode_replay)(&resp->xdr, op);
			status = op->status = op->replay->rp_status;
		} else {
			(*klpe_nfsd4_encode_operation)(resp, op);
			status = op->status;
		}

		klpr_dprintk("nfsv4 compound op %p opcnt %d #%d: %d: status %d\n",
				args->ops, args->opcnt, resp->opcnt, op->opnum,
				ntohl(status));

		(*klpe_nfsd4_cstate_clear_replay)(cstate);
		klpr_nfsd4_increment_op_stats(op->opnum);
	}

	cstate->status = status;
	(*klpe_fh_put)(current_fh);
	(*klpe_fh_put)(save_fh);
	BUG_ON(cstate->replay_owner);
out:
	/* Reset deferral mechanism for RPC deferrals */
	set_bit(RQ_USEDEFERRAL, &rqstp->rq_flags);
	klpr_dprintk("nfsv4 compound returned %d\n", ntohl(status));
	return status;
}

#define op_encode_hdr_size		(2)

#define op_encode_verifier_maxsz	(XDR_QUADLEN(NFS4_VERIFIER_SIZE))

static u32 nfsd4_max_payload(const struct svc_rqst *rqstp)
{
	u32 buflen;

	buflen = (rqstp->rq_page_end - rqstp->rq_next_page) * PAGE_SIZE;
	buflen -= rqstp->rq_auth_slack;
	buflen -= rqstp->rq_res.head[0].iov_len;
	return min_t(u32, buflen, (*klpe_svc_max_payload)(rqstp));
}

static inline u32 klpp_nfsd4_getattr_rsize(struct svc_rqst *rqstp,
				      struct nfsd4_op *op)
{
	u32 *bmap = op->u.getattr.ga_bmval;
	u32 bmap0 = bmap[0], bmap1 = bmap[1], bmap2 = bmap[2];
	u32 ret = 0;

	if (bmap0 & FATTR4_WORD0_ACL)
		return nfsd4_max_payload(rqstp);
	if (bmap0 & FATTR4_WORD0_FS_LOCATIONS)
		return nfsd4_max_payload(rqstp);

	if (bmap1 & FATTR4_WORD1_OWNER) {
		ret += IDMAP_NAMESZ + 4;
		bmap1 &= ~FATTR4_WORD1_OWNER;
	}
	if (bmap1 & FATTR4_WORD1_OWNER_GROUP) {
		ret += IDMAP_NAMESZ + 4;
		bmap1 &= ~FATTR4_WORD1_OWNER_GROUP;
	}
	if (bmap0 & FATTR4_WORD0_FILEHANDLE) {
		ret += NFS4_FHSIZE + 4;
		bmap0 &= ~FATTR4_WORD0_FILEHANDLE;
	}
	if (bmap2 & FATTR4_WORD2_SECURITY_LABEL) {
		ret += NFS4_MAXLABELLEN + 12;
		bmap2 &= ~FATTR4_WORD2_SECURITY_LABEL;
	}
	/*
	 * Largest of remaining attributes are 16 bytes (e.g.,
	 * supported_attributes)
	 */
	ret += 16 * (hweight32(bmap0) + hweight32(bmap1) + hweight32(bmap2));
	/* bitmask, length */
	ret += 20;
	return ret;
}

static inline u32 klpp_nfsd4_read_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	u32 rlen = min(op->u.read.rd_length, nfsd4_max_payload(rqstp));

	return (op_encode_hdr_size + 2 + XDR_QUADLEN(rlen)) * sizeof(__be32);
}

static inline u32 klpp_nfsd4_readdir_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	u32 rlen = min(op->u.readdir.rd_maxcount, nfsd4_max_payload(rqstp));

	return (op_encode_hdr_size + op_encode_verifier_maxsz +
		XDR_QUADLEN(rlen)) * sizeof(__be32);
}

static inline u32 klpp_nfsd4_getdeviceinfo_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	u32 rlen = min(op->u.getdeviceinfo.gd_maxcount, nfsd4_max_payload(rqstp));

	return (op_encode_hdr_size +
		1 /* gd_layout_type*/ +
		XDR_QUADLEN(rlen) +
		2 /* gd_notify_types */) * sizeof(__be32);
}

static u32 (*klpe_nfsd4_getattr_rsize)(struct svc_rqst *rqstp,
		struct nfsd4_op *op);
static u32 (*klpe_nfsd4_read_rsize)(struct svc_rqst *rqstp,
		struct nfsd4_op *op);
static u32 (*klpe_nfsd4_readdir_rsize)(struct svc_rqst *rqstp,
		struct nfsd4_op *op);
static u32 (*klpe_nfsd4_getdeviceinfo_rsize)(struct svc_rqst *rqstp,
		struct nfsd4_op *op);

static int rsize_bop(nfsd4op_rsize op_rsize_bop,
		struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	if (op_rsize_bop == klpe_nfsd4_getattr_rsize)
		return klpp_nfsd4_getattr_rsize(rqstp, op);
	else if (op_rsize_bop == klpe_nfsd4_read_rsize)
		return klpp_nfsd4_read_rsize(rqstp, op);
	else if (op_rsize_bop == klpe_nfsd4_readdir_rsize)
		return klpp_nfsd4_readdir_rsize(rqstp, op);
	else if (op_rsize_bop == klpe_nfsd4_getdeviceinfo_rsize)
		return klpp_nfsd4_getdeviceinfo_rsize(rqstp, op);

	return op_rsize_bop(rqstp, op);
}

int klpp_nfsd4_max_reply(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	if (op->opnum == OP_ILLEGAL || op->status == nfserr_notsupp)
		return op_encode_hdr_size * sizeof(__be32);

	BUG_ON(klpr_OPDESC(op)->op_rsize_bop == NULL);
	return rsize_bop(klpr_OPDESC(op)->op_rsize_bop, rqstp, op);
}

static const char *klpr_nfsd4_op_name(unsigned opnum)
{
	if (opnum < ARRAY_SIZE((*klpe_nfsd4_ops)))
		return (*klpe_nfsd4_ops)[opnum].op_name;
	return "unknown_operation";
}



#define LP_MODULE "nfsd"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1205130.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "check_nfsd_access", (void *)&klpe_check_nfsd_access, "nfsd" },
	{ "clear_current_stateid", (void *)&klpe_clear_current_stateid,
	  "nfsd" },
	{ "fh_put", (void *)&klpe_fh_put, "nfsd" },
	{ "nfsd4_check_resp_size", (void *)&klpe_nfsd4_check_resp_size,
	  "nfsd" },
	{ "nfsd4_cstate_clear_replay", (void *)&klpe_nfsd4_cstate_clear_replay,
	  "nfsd" },
	{ "nfsd4_encode_operation", (void *)&klpe_nfsd4_encode_operation,
	  "nfsd" },
	{ "nfsd4_encode_replay", (void *)&klpe_nfsd4_encode_replay, "nfsd" },
	{ "nfsd4_open", (void *)&klpe_nfsd4_open, "nfsd" },
	{ "nfsd4_ops", (void *)&klpe_nfsd4_ops, "nfsd" },
	{ "nfsd_debug", (void *)&klpe_nfsd_debug, "sunrpc" },
	{ "nfsd_minorversion", (void *)&klpe_nfsd_minorversion, "nfsd" },
	{ "nfsdstats", (void *)&klpe_nfsdstats, "nfsd" },
	{ "nfsd4_getattr_rsize", (void *)&klpe_nfsd4_getattr_rsize, "nfsd" },
	{ "nfsd4_read_rsize", (void *)&klpe_nfsd4_read_rsize, "nfsd" },
	{ "nfsd4_readdir_rsize", (void *)&klpe_nfsd4_readdir_rsize, "nfsd" },
	{ "nfsd4_getdeviceinfo_rsize", (void *)&klpe_nfsd4_getdeviceinfo_rsize,
	  "nfsd" },
	{ "svc_max_payload", (void *)&klpe_svc_max_payload, "sunrpc" },
	{ "xdr_reserve_space", (void *)&klpe_xdr_reserve_space, "sunrpc" },
};

static int bsc1205130_fs_nfsd_nfs4proc_module_notify(struct notifier_block *nb,
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
	.notifier_call = bsc1205130_fs_nfsd_nfs4proc_module_notify,
	.priority = INT_MIN+1,
};

int bsc1205130_fs_nfsd_nfs4proc_init(void)
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

void bsc1205130_fs_nfsd_nfs4proc_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
