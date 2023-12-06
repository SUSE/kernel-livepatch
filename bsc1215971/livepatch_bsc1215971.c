/*
 * livepatch_bsc1215971
 *
 * Fix for CVE-2023-5345, bsc#1215971
 *
 *  Upstream commit:
 *  e6e43b8aa7cd ("fs/smb/client: Reset password pointer to NULL")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  679511d5e9b604d4a6e02645bfd50b948b16465f
 *
 *  Copyright (c) 2023 SUSE
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

#if !IS_MODULE(CONFIG_CIFS)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from fs/smb/client/fs_context.c */
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/utsname.h>
/* klp-ccp: from fs/smb/client/cifsfs.h */
#include <linux/hash.h>
/* klp-ccp: from fs/smb/client/cifspdu.h */
#include <net/sock.h>
#include <asm/unaligned.h>

#define CIFS_MAX_MSGSIZE (4*4096)

#define UNKNOWN_TYPE		0xFFFF

typedef struct {
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le32 Attributes;
	__u32 Pad;
} __attribute__((packed)) FILE_BASIC_INFO;

/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <linux/in.h>
#include <linux/in6.h>

/* klp-ccp: from include/linux/inet.h */
#define _LINUX_INET_H

/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
#include <linux/utsname.h>
#include <linux/sched/mm.h>
/* klp-ccp: from fs/smb/client/cifs_fs_sb.h */
#include <linux/rbtree.h>

#ifndef _CIFS_FS_SB_H

struct cifs_sb_info {
	struct rb_root tlink_tree;
	spinlock_t tlink_tree_lock;
	struct tcon_link *master_tlink;
	struct nls_table *local_nls;
	struct smb3_fs_context *ctx;
	atomic_t active;
	unsigned int mnt_cifs_flags;
	struct delayed_work prune_tlinks;
	struct rcu_head rcu;

	/* only used when CIFS_MOUNT_USE_PREFIX_PATH is set */
	char *prepath;

	/*
	 * Indicate whether serverino option was turned off later
	 * (cifs_autodisable_serverino) in order to match new mounts.
	 */
	bool mnt_cifs_serverino_autodisabled;
	/*
	 * Available once the mount has completed.
	 */
	struct dentry *root;
};
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif				/* _CIFS_FS_SB_H */

/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <uapi/linux/cifs/cifs_mount.h>

/* klp-ccp: from fs/smb/common/smb2pdu.h */
#define SMB3_DEFAULT_IOSIZE (4 * 1024 * 1024)

#define SMB2_CLIENT_GUID_SIZE		16

/* klp-ccp: from fs/smb/client/smb2pdu.h */
#include <net/sock.h>

/* klp-ccp: from fs/smb/client/cifsglob.h */
#define CIFS_DEF_ACTIMEO (1 * HZ)

#define CIFS_MAX_ACTIMEO (1 << 30)

#define SMB3_MAX_HANDLE_TIMEOUT 960000

#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

#define CIFS_MAX_WORKSTATION_LEN  (__NEW_UTS_LEN + 1)  /* reasonable max for client */

enum securityEnum {
	Unspecified = 0,	/* not specified */
	LANMAN,			/* Legacy LANMAN auth */
	NTLM,			/* Legacy NTLM012 auth with NTLM hash */
	NTLMv2,			/* Legacy NTLM auth with NTLMv2 hash */
	RawNTLMSSP,		/* NTLMSSP without SPNEGO, NTLMv2 hash */
	Kerberos,		/* Kerberos via SPNEGO */
};

struct cifs_open_info_data;

struct smb_rqst;

struct mid_q_entry;
struct TCP_Server_Info;
struct cifsFileInfo;
struct cifs_ses;
struct cifs_tcon;
struct dfs_info3_param;

struct cifs_fid;
struct cifs_readdata;
struct cifs_writedata;
struct cifs_io_parms;
struct cifs_search_info;
struct cifsInodeInfo;
struct cifs_open_parms;
struct cifs_credits;

struct smb_version_operations {
	int (*send_cancel)(struct TCP_Server_Info *, struct smb_rqst *,
			   struct mid_q_entry *);
	bool (*compare_fids)(struct cifsFileInfo *, struct cifsFileInfo *);
	/* setup request: allocate mid, sign message */
	struct mid_q_entry *(*setup_request)(struct cifs_ses *,
					     struct TCP_Server_Info *,
					     struct smb_rqst *);
	/* setup async request: allocate mid, sign message */
	struct mid_q_entry *(*setup_async_request)(struct TCP_Server_Info *,
						struct smb_rqst *);
	/* check response: verify signature, map error */
	int (*check_receive)(struct mid_q_entry *, struct TCP_Server_Info *,
			     bool);
	void (*add_credits)(struct TCP_Server_Info *server,
			    const struct cifs_credits *credits,
			    const int optype);
	void (*set_credits)(struct TCP_Server_Info *, const int);
	int * (*get_credits_field)(struct TCP_Server_Info *, const int);
	unsigned int (*get_credits)(struct mid_q_entry *);
	__u64 (*get_next_mid)(struct TCP_Server_Info *);
	void (*revert_current_mid)(struct TCP_Server_Info *server,
				   const unsigned int val);
	/* data offset from read response message */
	unsigned int (*read_data_offset)(char *);
	/*
	 * Data length from read response message
	 * When in_remaining is true, the returned data length is in
	 * message field DataRemaining for out-of-band data read (e.g through
	 * Memory Registration RDMA write in SMBD).
	 * Otherwise, the returned data length is in message field DataLength.
	 */
	unsigned int (*read_data_length)(char *, bool in_remaining);
	/* map smb to linux error */
	int (*map_error)(char *, bool);
	/* find mid corresponding to the response message */
	struct mid_q_entry * (*find_mid)(struct TCP_Server_Info *, char *);
	void (*dump_detail)(void *buf, struct TCP_Server_Info *ptcp_info);
	void (*clear_stats)(struct cifs_tcon *);
	void (*print_stats)(struct seq_file *m, struct cifs_tcon *);
	void (*dump_share_caps)(struct seq_file *, struct cifs_tcon *);
	/* verify the message */
	int (*check_message)(char *, unsigned int, struct TCP_Server_Info *);
	bool (*is_oplock_break)(char *, struct TCP_Server_Info *);
	int (*handle_cancelled_mid)(struct mid_q_entry *, struct TCP_Server_Info *);
	void (*downgrade_oplock)(struct TCP_Server_Info *server,
				 struct cifsInodeInfo *cinode, __u32 oplock,
				 unsigned int epoch, bool *purge_cache);
	/* process transaction2 response */
	bool (*check_trans2)(struct mid_q_entry *, struct TCP_Server_Info *,
			     char *, int);
	/* check if we need to negotiate */
	bool (*need_neg)(struct TCP_Server_Info *);
	/* negotiate to the server */
	int (*negotiate)(const unsigned int xid,
			 struct cifs_ses *ses,
			 struct TCP_Server_Info *server);
	/* set negotiated write size */
	unsigned int (*negotiate_wsize)(struct cifs_tcon *tcon, struct smb3_fs_context *ctx);
	/* set negotiated read size */
	unsigned int (*negotiate_rsize)(struct cifs_tcon *tcon, struct smb3_fs_context *ctx);
	/* setup smb sessionn */
	int (*sess_setup)(const unsigned int, struct cifs_ses *,
			  struct TCP_Server_Info *server,
			  const struct nls_table *);
	/* close smb session */
	int (*logoff)(const unsigned int, struct cifs_ses *);
	/* connect to a server share */
	int (*tree_connect)(const unsigned int, struct cifs_ses *, const char *,
			    struct cifs_tcon *, const struct nls_table *);
	/* close tree connecion */
	int (*tree_disconnect)(const unsigned int, struct cifs_tcon *);
	/* get DFS referrals */
	int (*get_dfs_refer)(const unsigned int, struct cifs_ses *,
			     const char *, struct dfs_info3_param **,
			     unsigned int *, const struct nls_table *, int);
	/* informational QFS call */
	void (*qfs_tcon)(const unsigned int, struct cifs_tcon *,
			 struct cifs_sb_info *);
	/* check if a path is accessible or not */
	int (*is_path_accessible)(const unsigned int, struct cifs_tcon *,
				  struct cifs_sb_info *, const char *);
	/* query path data from the server */
	int (*query_path_info)(const unsigned int xid, struct cifs_tcon *tcon,
			       struct cifs_sb_info *cifs_sb, const char *full_path,
			       struct cifs_open_info_data *data, bool *adjust_tz, bool *reparse);
	/* query file data from the server */
	int (*query_file_info)(const unsigned int xid, struct cifs_tcon *tcon,
			       struct cifsFileInfo *cfile, struct cifs_open_info_data *data);
	/* query reparse tag from srv to determine which type of special file */
	int (*query_reparse_tag)(const unsigned int xid, struct cifs_tcon *tcon,
				struct cifs_sb_info *cifs_sb, const char *path,
				__u32 *reparse_tag);
	/* get server index number */
	int (*get_srv_inum)(const unsigned int xid, struct cifs_tcon *tcon,
			    struct cifs_sb_info *cifs_sb, const char *full_path, u64 *uniqueid,
			    struct cifs_open_info_data *data);
	/* set size by path */
	int (*set_path_size)(const unsigned int, struct cifs_tcon *,
			     const char *, __u64, struct cifs_sb_info *, bool);
	/* set size by file handle */
	int (*set_file_size)(const unsigned int, struct cifs_tcon *,
			     struct cifsFileInfo *, __u64, bool);
	/* set attributes */
	int (*set_file_info)(struct inode *, const char *, FILE_BASIC_INFO *,
			     const unsigned int);
	int (*set_compression)(const unsigned int, struct cifs_tcon *,
			       struct cifsFileInfo *);
	/* check if we can send an echo or nor */
	bool (*can_echo)(struct TCP_Server_Info *);
	/* send echo request */
	int (*echo)(struct TCP_Server_Info *);
	/* create directory */
	int (*posix_mkdir)(const unsigned int xid, struct inode *inode,
			umode_t mode, struct cifs_tcon *tcon,
			const char *full_path,
			struct cifs_sb_info *cifs_sb);
	int (*mkdir)(const unsigned int xid, struct inode *inode, umode_t mode,
		     struct cifs_tcon *tcon, const char *name,
		     struct cifs_sb_info *sb);
	/* set info on created directory */
	void (*mkdir_setinfo)(struct inode *, const char *,
			      struct cifs_sb_info *, struct cifs_tcon *,
			      const unsigned int);
	/* remove directory */
	int (*rmdir)(const unsigned int, struct cifs_tcon *, const char *,
		     struct cifs_sb_info *);
	/* unlink file */
	int (*unlink)(const unsigned int, struct cifs_tcon *, const char *,
		      struct cifs_sb_info *);
	/* open, rename and delete file */
	int (*rename_pending_delete)(const char *, struct dentry *,
				     const unsigned int);
	/* send rename request */
	int (*rename)(const unsigned int, struct cifs_tcon *, const char *,
		      const char *, struct cifs_sb_info *);
	/* send create hardlink request */
	int (*create_hardlink)(const unsigned int, struct cifs_tcon *,
			       const char *, const char *,
			       struct cifs_sb_info *);
	/* query symlink target */
	int (*query_symlink)(const unsigned int, struct cifs_tcon *,
			     struct cifs_sb_info *, const char *,
			     char **, bool);
	/* open a file for non-posix mounts */
	int (*open)(const unsigned int xid, struct cifs_open_parms *oparms, __u32 *oplock,
		    void *buf);
	/* set fid protocol-specific info */
	void (*set_fid)(struct cifsFileInfo *, struct cifs_fid *, __u32);
	/* close a file */
	void (*close)(const unsigned int, struct cifs_tcon *,
		      struct cifs_fid *);
	/* close a file, returning file attributes and timestamps */
	void (*close_getattr)(const unsigned int xid, struct cifs_tcon *tcon,
		      struct cifsFileInfo *pfile_info);
	/* send a flush request to the server */
	int (*flush)(const unsigned int, struct cifs_tcon *, struct cifs_fid *);
	/* async read from the server */
	int (*async_readv)(struct cifs_readdata *);
	/* async write to the server */
	int (*async_writev)(struct cifs_writedata *,
			    void (*release)(struct kref *));
	/* sync read from the server */
	int (*sync_read)(const unsigned int, struct cifs_fid *,
			 struct cifs_io_parms *, unsigned int *, char **,
			 int *);
	/* sync write to the server */
	int (*sync_write)(const unsigned int, struct cifs_fid *,
			  struct cifs_io_parms *, unsigned int *, struct kvec *,
			  unsigned long);
	/* open dir, start readdir */
	int (*query_dir_first)(const unsigned int, struct cifs_tcon *,
			       const char *, struct cifs_sb_info *,
			       struct cifs_fid *, __u16,
			       struct cifs_search_info *);
	/* continue readdir */
	int (*query_dir_next)(const unsigned int, struct cifs_tcon *,
			      struct cifs_fid *,
			      __u16, struct cifs_search_info *srch_inf);
	/* close dir */
	int (*close_dir)(const unsigned int, struct cifs_tcon *,
			 struct cifs_fid *);
	/* calculate a size of SMB message */
	unsigned int (*calc_smb_size)(void *buf);
	/* check for STATUS_PENDING and process the response if yes */
	bool (*is_status_pending)(char *buf, struct TCP_Server_Info *server);
	/* check for STATUS_NETWORK_SESSION_EXPIRED */
	bool (*is_session_expired)(char *);
	/* send oplock break response */
	int (*oplock_response)(struct cifs_tcon *tcon, __u64 persistent_fid, __u64 volatile_fid,
			__u16 net_fid, struct cifsInodeInfo *cifs_inode);
	/* query remote filesystem */
	int (*queryfs)(const unsigned int, struct cifs_tcon *,
		       struct cifs_sb_info *, struct kstatfs *);
	/* send mandatory brlock to the server */
	int (*mand_lock)(const unsigned int, struct cifsFileInfo *, __u64,
			 __u64, __u32, int, int, bool);
	/* unlock range of mandatory locks */
	int (*mand_unlock_range)(struct cifsFileInfo *, struct file_lock *,
				 const unsigned int);
	/* push brlocks from the cache to the server */
	int (*push_mand_locks)(struct cifsFileInfo *);
	/* get lease key of the inode */
	void (*get_lease_key)(struct inode *, struct cifs_fid *);
	/* set lease key of the inode */
	void (*set_lease_key)(struct inode *, struct cifs_fid *);
	/* generate new lease key */
	void (*new_lease_key)(struct cifs_fid *);
	int (*generate_signingkey)(struct cifs_ses *ses,
				   struct TCP_Server_Info *server);
	int (*calc_signature)(struct smb_rqst *, struct TCP_Server_Info *,
				bool allocate_crypto);
	int (*set_integrity)(const unsigned int, struct cifs_tcon *tcon,
			     struct cifsFileInfo *src_file);
	int (*enum_snapshots)(const unsigned int xid, struct cifs_tcon *tcon,
			     struct cifsFileInfo *src_file, void __user *);
	int (*notify)(const unsigned int xid, struct file *pfile,
			     void __user *pbuf, bool return_changes);
	int (*query_mf_symlink)(unsigned int, struct cifs_tcon *,
				struct cifs_sb_info *, const unsigned char *,
				char *, unsigned int *);
	int (*create_mf_symlink)(unsigned int, struct cifs_tcon *,
				 struct cifs_sb_info *, const unsigned char *,
				 char *, unsigned int *);
	/* if we can do cache read operations */
	bool (*is_read_op)(__u32);
	/* set oplock level for the inode */
	void (*set_oplock_level)(struct cifsInodeInfo *, __u32, unsigned int,
				 bool *);
	/* create lease context buffer for CREATE request */
	char * (*create_lease_buf)(u8 *lease_key, u8 oplock);
	/* parse lease context buffer and return oplock/epoch info */
	__u8 (*parse_lease_buf)(void *buf, unsigned int *epoch, char *lkey);
	ssize_t (*copychunk_range)(const unsigned int,
			struct cifsFileInfo *src_file,
			struct cifsFileInfo *target_file,
			u64 src_off, u64 len, u64 dest_off);
	int (*duplicate_extents)(const unsigned int, struct cifsFileInfo *src,
			struct cifsFileInfo *target_file, u64 src_off, u64 len,
			u64 dest_off);
	int (*validate_negotiate)(const unsigned int, struct cifs_tcon *);
	ssize_t (*query_all_EAs)(const unsigned int, struct cifs_tcon *,
			const unsigned char *, const unsigned char *, char *,
			size_t, struct cifs_sb_info *);
	int (*set_EA)(const unsigned int, struct cifs_tcon *, const char *,
			const char *, const void *, const __u16,
			const struct nls_table *, struct cifs_sb_info *);
	struct cifs_ntsd * (*get_acl)(struct cifs_sb_info *, struct inode *,
			const char *, u32 *, u32);
	struct cifs_ntsd * (*get_acl_by_fid)(struct cifs_sb_info *,
			const struct cifs_fid *, u32 *, u32);
	int (*set_acl)(struct cifs_ntsd *, __u32, struct inode *, const char *,
			int);
	/* writepages retry size */
	unsigned int (*wp_retry_size)(struct inode *);
	/* get mtu credits */
	int (*wait_mtu_credits)(struct TCP_Server_Info *, unsigned int,
				unsigned int *, struct cifs_credits *);
	/* adjust previously taken mtu credits to request size */
	int (*adjust_credits)(struct TCP_Server_Info *server,
			      struct cifs_credits *credits,
			      const unsigned int payload_size);
	/* check if we need to issue closedir */
	bool (*dir_needs_close)(struct cifsFileInfo *);
	long (*fallocate)(struct file *, struct cifs_tcon *, int, loff_t,
			  loff_t);
	/* init transform request - used for encryption for now */
	int (*init_transform_rq)(struct TCP_Server_Info *, int num_rqst,
				 struct smb_rqst *, struct smb_rqst *);
	int (*is_transform_hdr)(void *buf);
	int (*receive_transform)(struct TCP_Server_Info *,
				 struct mid_q_entry **, char **, int *);
	enum securityEnum (*select_sectype)(struct TCP_Server_Info *,
			    enum securityEnum);
	int (*next_header)(char *);
	/* ioctl passthrough for query_info */
	int (*ioctl_query_info)(const unsigned int xid,
				struct cifs_tcon *tcon,
				struct cifs_sb_info *cifs_sb,
				__le16 *path, int is_dir,
				unsigned long p);
	/* make unix special files (block, char, fifo, socket) */
	int (*make_node)(unsigned int xid,
			 struct inode *inode,
			 struct dentry *dentry,
			 struct cifs_tcon *tcon,
			 const char *full_path,
			 umode_t mode,
			 dev_t device_number);
	/* version specific fiemap implementation */
	int (*fiemap)(struct cifs_tcon *tcon, struct cifsFileInfo *,
		      struct fiemap_extent_info *, u64, u64);
	/* version specific llseek implementation */
	loff_t (*llseek)(struct file *, struct cifs_tcon *, loff_t, int);
	/* Check for STATUS_IO_TIMEOUT */
	bool (*is_status_io_timeout)(char *buf);
	/* Check for STATUS_NETWORK_NAME_DELETED */
	bool (*is_network_name_deleted)(char *buf, struct TCP_Server_Info *srv);
};

struct smb_version_values {
	char		*version_string;
	__u16		protocol_id;
	__u32		req_capabilities;
	__u32		large_lock_type;
	__u32		exclusive_lock_type;
	__u32		shared_lock_type;
	__u32		unlock_lock_type;
	size_t		header_preamble_size;
	size_t		header_size;
	size_t		max_header_size;
	size_t		read_rsp_size;
	__le16		lock_cmd;
	unsigned int	cap_unix;
	unsigned int	cap_nt_find;
	unsigned int	cap_large_files;
	__u16		signing_enabled;
	__u16		signing_required;
	size_t		create_lease_size;
};

#define CIFS_DEFAULT_IOSIZE (1024 * 1024)

#define CIFS_MAX_CHANNELS 16

static bool (*klpe_disable_legacy_dialects);

#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
static struct smb_version_operations (*klpe_smb1_operations);
static struct smb_version_values (*klpe_smb1_values);
static struct smb_version_operations (*klpe_smb20_operations);
static struct smb_version_values (*klpe_smb20_values);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CIFS_ALLOW_INSECURE_LEGACY */

static struct smb_version_operations (*klpe_smb21_operations);
static struct smb_version_values (*klpe_smb21_values);

static struct smb_version_values (*klpe_smbdefault_values);

static struct smb_version_values (*klpe_smb3any_values);

static struct smb_version_operations (*klpe_smb30_operations);
static struct smb_version_values (*klpe_smb30_values);

static struct smb_version_values (*klpe_smb302_values);

static struct smb_version_operations (*klpe_smb311_operations);
static struct smb_version_values (*klpe_smb311_values);

/* klp-ccp: from include/linux/nls.h */
#define _LINUX_NLS_H

/* klp-ccp: from fs/smb/client/cifsproto.h */
#include <linux/ctype.h>

/* klp-ccp: from fs/smb/client/trace.h */
#if !defined(_CIFS_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)

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

static char *(*klpe_smb3_fs_context_fullpath)(const struct smb3_fs_context *ctx,
				      char dirsep);
static int (*klpe_smb3_parse_devname)(const char *devname, struct smb3_fs_context *ctx);

static int (*klpe_cifs_convert_address)(struct sockaddr *dst, const char *src, int len);

/* klp-ccp: from fs/smb/client/cifs_unicode.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/nls.h>

/* klp-ccp: from fs/smb/client/cifs_debug.h */
#undef pr_fmt
#define pr_fmt(fmt) "CIFS: " fmt

static int (*klpe_cifsFYI);

/* klp-ccp: from fs/smb/client/cifs_fs_sb.h */
#include <linux/rbtree.h>
/* klp-ccp: from fs/smb/client/fs_context.h */
#include <linux/parser.h>
#include <linux/fs_parser.h>

enum smb_version {
	Smb_1 = 1,
	Smb_20,
	Smb_21,
	Smb_30,
	Smb_302,
	Smb_311,
	Smb_3any,
	Smb_default,
	Smb_version_err
};

enum {
	Opt_cache_loose,
	Opt_cache_strict,
	Opt_cache_none,
	Opt_cache_ro,
	Opt_cache_rw,
	Opt_cache_err
};

enum cifs_sec_param {
	Opt_sec_krb5,
	Opt_sec_krb5i,
	Opt_sec_krb5p,
	Opt_sec_ntlmsspi,
	Opt_sec_ntlmssp,
	Opt_ntlm,
	Opt_sec_ntlmi,
	Opt_sec_ntlmv2,
	Opt_sec_ntlmv2i,
	Opt_sec_lanman,
	Opt_sec_none,

	Opt_sec_err
};

enum cifs_param {
	/* Mount options that take no arguments */
	Opt_user_xattr,
	Opt_forceuid,
	Opt_forcegid,
	Opt_noblocksend,
	Opt_noautotune,
	Opt_nolease,
	Opt_nosparse,
	Opt_hard,
	Opt_soft,
	Opt_perm,
	Opt_nodelete,
	Opt_mapposix,
	Opt_mapchars,
	Opt_nomapchars,
	Opt_sfu,
	Opt_nodfs,
	Opt_posixpaths,
	Opt_unix,
	Opt_nocase,
	Opt_brl,
	Opt_handlecache,
	Opt_forcemandatorylock,
	Opt_setuidfromacl,
	Opt_setuids,
	Opt_dynperm,
	Opt_intr,
	Opt_strictsync,
	Opt_serverino,
	Opt_rwpidforward,
	Opt_cifsacl,
	Opt_acl,
	Opt_locallease,
	Opt_sign,
	Opt_ignore_signature,
	Opt_seal,
	Opt_noac,
	Opt_fsc,
	Opt_mfsymlinks,
	Opt_multiuser,
	Opt_sloppy,
	Opt_nosharesock,
	Opt_persistent,
	Opt_resilient,
	Opt_tcp_nodelay,
	Opt_domainauto,
	Opt_rdma,
	Opt_modesid,
	Opt_rootfs,
	Opt_multichannel,
	Opt_compress,
	Opt_witness,

	/* Mount options which take numeric value */
	Opt_backupuid,
	Opt_backupgid,
	Opt_uid,
	Opt_cruid,
	Opt_gid,
	Opt_port,
	Opt_file_mode,
	Opt_dirmode,
	Opt_min_enc_offload,
	Opt_blocksize,
	Opt_rasize,
	Opt_rsize,
	Opt_wsize,
	Opt_actimeo,
	Opt_acdirmax,
	Opt_acregmax,
	Opt_closetimeo,
	Opt_echo_interval,
	Opt_max_credits,
	Opt_snapshot,
	Opt_max_channels,
	Opt_handletimeout,

	/* Mount options which take string value */
	Opt_source,
	Opt_user,
	Opt_pass,
	Opt_ip,
	Opt_domain,
	Opt_srcaddr,
	Opt_iocharset,
	Opt_netbiosname,
	Opt_servern,
	Opt_ver,
	Opt_vers,
	Opt_sec,
	Opt_cache,

	/* Mount options to be ignored */
	Opt_ignore,

	Opt_err
};

struct smb3_fs_context {
	bool uid_specified;
	bool cruid_specified;
	bool gid_specified;
	bool sloppy;
	bool got_ip;
	bool got_version;
	bool got_rsize;
	bool got_wsize;
	bool got_bsize;
	unsigned short port;

	char *username;
	char *password;
	char *domainname;
	char *source;
	char *server_hostname;
	char *UNC;
	char *nodename;
	char workstation_name[CIFS_MAX_WORKSTATION_LEN];
	char *iocharset;  /* local code page for mapping to and from Unicode */
	char source_rfc1001_name[RFC1001_NAME_LEN_WITH_NULL]; /* clnt nb name */
	char target_rfc1001_name[RFC1001_NAME_LEN_WITH_NULL]; /* srvr nb name */
	kuid_t cred_uid;
	kuid_t linux_uid;
	kgid_t linux_gid;
	kuid_t backupuid;
	kgid_t backupgid;
	umode_t file_mode;
	umode_t dir_mode;
	enum securityEnum sectype; /* sectype requested via mnt opts */
	bool sign; /* was signing requested via mnt opts? */
	bool ignore_signature:1;
	bool retry:1;
	bool intr:1;
	bool setuids:1;
	bool setuidfromacl:1;
	bool override_uid:1;
	bool override_gid:1;
	bool dynperm:1;
	bool noperm:1;
	bool nodelete:1;
	bool mode_ace:1;
	bool no_psx_acl:1; /* set if posix acl support should be disabled */
	bool cifs_acl:1;
	bool backupuid_specified; /* mount option  backupuid  is specified */
	bool backupgid_specified; /* mount option  backupgid  is specified */
	bool no_xattr:1;   /* set if xattr (EA) support should be disabled*/
	bool server_ino:1; /* use inode numbers from server ie UniqueId */
	bool direct_io:1;
	bool strict_io:1; /* strict cache behavior */
	bool cache_ro:1;
	bool cache_rw:1;
	bool remap:1;      /* set to remap seven reserved chars in filenames */
	bool sfu_remap:1;  /* remap seven reserved chars ala SFU */
	bool posix_paths:1; /* unset to not ask for posix pathnames. */
	bool no_linux_ext:1;
	bool linux_ext:1;
	bool sfu_emul:1;
	bool nullauth:1;   /* attempt to authenticate with null user */
	bool nocase:1;     /* request case insensitive filenames */
	bool nobrl:1;      /* disable sending byte range locks to srv */
	bool nohandlecache:1; /* disable caching dir handles if srvr probs */
	bool mand_lock:1;  /* send mandatory not posix byte range lock reqs */
	bool seal:1;       /* request transport encryption on share */
	bool nodfs:1;      /* Do not request DFS, even if available */
	bool local_lease:1; /* check leases only on local system, not remote */
	bool noblocksnd:1;
	bool noautotune:1;
	bool nostrictsync:1; /* do not force expensive SMBflush on every sync */
	bool no_lease:1;     /* disable requesting leases */
	bool no_sparse:1;    /* do not attempt to set files sparse */
	bool fsc:1;	/* enable fscache */
	bool mfsymlinks:1; /* use Minshall+French Symlinks */
	bool multiuser:1;
	bool rwpidforward:1; /* pid forward for read/write operations */
	bool nosharesock:1;
	bool persistent:1;
	bool nopersistent:1;
	bool resilient:1; /* noresilient not required since not fored for CA */
	bool domainauto:1;
	bool rdma:1;
	bool multichannel:1;
	bool use_client_guid:1;
	/* reuse existing guid for multichannel */
	u8 client_guid[SMB2_CLIENT_GUID_SIZE];
	unsigned int bsize;
	unsigned int rasize;
	unsigned int rsize;
	unsigned int wsize;
	unsigned int min_offload;
	bool sockopt_tcp_nodelay:1;
	/* attribute cache timemout for files and directories in jiffies */
	unsigned long acregmax;
	unsigned long acdirmax;
	/* timeout for deferred close of files in jiffies */
	unsigned long closetimeo;
	struct smb_version_operations *ops;
	struct smb_version_values *vals;
	char *prepath;
	struct sockaddr_storage dstaddr; /* destination address */
	struct sockaddr_storage srcaddr; /* allow binding to a local IP */
	struct nls_table *local_nls; /* This is a copy of the pointer in cifs_sb */
	unsigned int echo_interval; /* echo interval in secs */
	__u64 snapshot_time; /* needed for timewarp tokens */
	__u32 handle_timeout; /* persistent and durable handle timeout in ms */
	unsigned int max_credits; /* smb3 max_credits 10 < credits < 60000 */
	unsigned int max_channels;
	__u16 compression; /* compression algorithm 0xFFFF default 0=disabled */
	bool rootfs:1; /* if it's a SMB root file system */
	bool witness:1; /* use witness protocol */
	char *leaf_fullpath;
	struct cifs_ses *dfs_root_ses;
};

static const struct fs_parameter_spec (*klpe_smb3_fs_parameters)[];

static inline struct smb3_fs_context *smb3_fc2context(const struct fs_context *fc)
{
	return fc->fs_private;
}

#define SMB3_MAX_DCLOSETIMEO (1 << 30)

/* klp-ccp: from fs/smb/client/fs_context.c */
static const match_table_t (*klpe_cifs_smb_version_tokens);

static const match_table_t (*klpe_cifs_secflavor_tokens);

#define CIFS_INFO	0x01
#define VFS 1
#define FYI 2
#ifdef CONFIG_CIFS_DEBUG2
#define NOISY 4
#else
#define NOISY 0
#endif
#define ONCE 8

#define klpr_cifs_dbg_func(ratefunc, type, fmt, ...)				\
do {									\
	if ((type) & FYI && (*klpe_cifsFYI) & CIFS_INFO) {			\
		pr_debug_ ## ratefunc("%s: " fmt,			\
				      __FILE__, ##__VA_ARGS__);		\
	} else if ((type) & VFS) {					\
		pr_err_ ## ratefunc("VFS: " fmt, ##__VA_ARGS__);	\
	} else if ((type) & NOISY && (NOISY != 0)) {			\
		pr_debug_ ## ratefunc(fmt, ##__VA_ARGS__);		\
	}								\
} while (0)

#define cifs_dbg(type, fmt, ...)					\
do {									\
	if ((type) & ONCE)						\
		klpr_cifs_dbg_func(once, type, fmt, ##__VA_ARGS__);		\
	else								\
		klpr_cifs_dbg_func(ratelimited, type, fmt, ##__VA_ARGS__);	\
} while (0)

#define cifs_errorf(fc, fmt, ...)			\
	do {						\
		errorf(fc, fmt, ## __VA_ARGS__);	\
		cifs_dbg(VFS, fmt, ## __VA_ARGS__);	\
	} while (0)

static int
klpr_cifs_parse_security_flavors(struct fs_context *fc, char *value, struct smb3_fs_context *ctx)
{

	substring_t args[MAX_OPT_ARGS];

	/*
	 * With mount options, the last one should win. Reset any existing
	 * settings back to default.
	 */
	ctx->sectype = Unspecified;
	ctx->sign = false;

	switch (match_token(value, (*klpe_cifs_secflavor_tokens), args)) {
	case Opt_sec_krb5p:
		cifs_errorf(fc, "sec=krb5p is not supported!\n");
		return 1;
	case Opt_sec_krb5i:
		ctx->sign = true;
		fallthrough;
	case Opt_sec_krb5:
		ctx->sectype = Kerberos;
		break;
	case Opt_sec_ntlmsspi:
		ctx->sign = true;
		fallthrough;
	case Opt_sec_ntlmssp:
		ctx->sectype = RawNTLMSSP;
		break;
	case Opt_sec_ntlmi:
		ctx->sign = true;
		fallthrough;
	case Opt_ntlm:
		ctx->sectype = NTLM;
		break;
	case Opt_sec_ntlmv2i:
		ctx->sign = true;
		fallthrough;
	case Opt_sec_ntlmv2:
		ctx->sectype = NTLMv2;
		break;
#ifdef CONFIG_CIFS_WEAK_PW_HASH
	case Opt_sec_lanman:
		ctx->sectype = LANMAN;
		break;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	case Opt_sec_none:
		ctx->nullauth = 1;
		kfree(ctx->username);
		ctx->username = NULL;
		break;
	default:
		cifs_errorf(fc, "bad security option: %s\n", value);
		return 1;
	}

	return 0;
}

static const match_table_t (*klpe_cifs_cacheflavor_tokens);

static int
klpr_cifs_parse_cache_flavor(struct fs_context *fc, char *value, struct smb3_fs_context *ctx)
{
	substring_t args[MAX_OPT_ARGS];

	switch (match_token(value, (*klpe_cifs_cacheflavor_tokens), args)) {
	case Opt_cache_loose:
		ctx->direct_io = false;
		ctx->strict_io = false;
		ctx->cache_ro = false;
		ctx->cache_rw = false;
		break;
	case Opt_cache_strict:
		ctx->direct_io = false;
		ctx->strict_io = true;
		ctx->cache_ro = false;
		ctx->cache_rw = false;
		break;
	case Opt_cache_none:
		ctx->direct_io = true;
		ctx->strict_io = false;
		ctx->cache_ro = false;
		ctx->cache_rw = false;
		break;
	case Opt_cache_ro:
		ctx->direct_io = false;
		ctx->strict_io = false;
		ctx->cache_ro = true;
		ctx->cache_rw = false;
		break;
	case Opt_cache_rw:
		ctx->direct_io = false;
		ctx->strict_io = false;
		ctx->cache_ro = false;
		ctx->cache_rw = true;
		break;
	default:
		cifs_errorf(fc, "bad cache= option: %s\n", value);
		return 1;
	}
	return 0;
}

static int
klpr_cifs_parse_smb_version(struct fs_context *fc, char *value, struct smb3_fs_context *ctx, bool is_smb3)
{
	substring_t args[MAX_OPT_ARGS];

	switch (match_token(value, (*klpe_cifs_smb_version_tokens), args)) {
#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	case Smb_1:
		if ((*klpe_disable_legacy_dialects)) {
			cifs_errorf(fc, "mount with legacy dialect disabled\n");
			return 1;
		}
		if (is_smb3) {
			cifs_errorf(fc, "vers=1.0 (cifs) not permitted when mounting with smb3\n");
			return 1;
		}
		cifs_errorf(fc, "Use of the less secure dialect vers=1.0 is not recommended unless required for access to very old servers\n");
		ctx->ops = &(*klpe_smb1_operations);
		ctx->vals = &(*klpe_smb1_values);
		break;
	case Smb_20:
		if ((*klpe_disable_legacy_dialects)) {
			cifs_errorf(fc, "mount with legacy dialect disabled\n");
			return 1;
		}
		if (is_smb3) {
			cifs_errorf(fc, "vers=2.0 not permitted when mounting with smb3\n");
			return 1;
		}
		ctx->ops = &(*klpe_smb20_operations);
		ctx->vals = &(*klpe_smb20_values);
		break;
#else
#error "klp-ccp: non-taken branch"
#endif /* CIFS_ALLOW_INSECURE_LEGACY */
	case Smb_21:
		ctx->ops = &(*klpe_smb21_operations);
		ctx->vals = &(*klpe_smb21_values);
		break;
	case Smb_30:
		ctx->ops = &(*klpe_smb30_operations);
		ctx->vals = &(*klpe_smb30_values);
		break;
	case Smb_302:
		ctx->ops = &(*klpe_smb30_operations); /* currently identical with 3.0 */
		ctx->vals = &(*klpe_smb302_values);
		break;
	case Smb_311:
		ctx->ops = &(*klpe_smb311_operations);
		ctx->vals = &(*klpe_smb311_values);
		break;
	case Smb_3any:
		ctx->ops = &(*klpe_smb30_operations); /* currently identical with 3.0 */
		ctx->vals = &(*klpe_smb3any_values);
		break;
	case Smb_default:
		ctx->ops = &(*klpe_smb30_operations);
		ctx->vals = &(*klpe_smbdefault_values);
		break;
	default:
		cifs_errorf(fc, "Unknown vers= option specified: %s\n", value);
		return 1;
	}
	return 0;
}

int klpp_smb3_fs_context_parse_param(struct fs_context *fc,
				      struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct smb3_fs_context *ctx = smb3_fc2context(fc);
	int i, opt;
	bool is_smb3 = !strcmp(fc->fs_type->name, "smb3");
	bool skip_parsing = false;
	kuid_t uid;
	kgid_t gid;

	cifs_dbg(FYI, "CIFS: parsing cifs mount option '%s'\n", param->key);

	/*
	 * fs_parse can not handle string options with an empty value so
	 * we will need special handling of them.
	 */
	if (param->type == fs_value_is_string && param->string[0] == 0) {
		if (!strcmp("pass", param->key) || !strcmp("password", param->key)) {
			skip_parsing = true;
			opt = Opt_pass;
		} else if (!strcmp("user", param->key) || !strcmp("username", param->key)) {
			skip_parsing = true;
			opt = Opt_user;
		}
	}

	if (!skip_parsing) {
		opt = fs_parse(fc, (*klpe_smb3_fs_parameters), param, &result);
		if (opt < 0)
			return ctx->sloppy ? 1 : opt;
	}

	switch (opt) {
	case Opt_compress:
		ctx->compression = UNKNOWN_TYPE;
		cifs_dbg(VFS,
			"SMB3 compression support is experimental\n");
		break;
	case Opt_nodfs:
		ctx->nodfs = 1;
		break;
	case Opt_hard:
		if (result.negated) {
			if (ctx->retry == 1)
				cifs_dbg(VFS, "conflicting hard vs. soft mount options\n");
			ctx->retry = 0;
		} else
			ctx->retry = 1;
		break;
	case Opt_soft:
		if (result.negated)
			ctx->retry = 1;
		else {
			if (ctx->retry == 1)
				cifs_dbg(VFS, "conflicting hard vs soft mount options\n");
			ctx->retry = 0;
		}
		break;
	case Opt_mapposix:
		if (result.negated)
			ctx->remap = false;
		else {
			ctx->remap = true;
			ctx->sfu_remap = false; /* disable SFU mapping */
		}
		break;
	case Opt_mapchars:
		if (result.negated)
			ctx->sfu_remap = false;
		else {
			ctx->sfu_remap = true;
			ctx->remap = false; /* disable SFM (mapposix) mapping */
		}
		break;
	case Opt_user_xattr:
		if (result.negated)
			ctx->no_xattr = 1;
		else
			ctx->no_xattr = 0;
		break;
	case Opt_forceuid:
		if (result.negated)
			ctx->override_uid = 0;
		else
			ctx->override_uid = 1;
		break;
	case Opt_forcegid:
		if (result.negated)
			ctx->override_gid = 0;
		else
			ctx->override_gid = 1;
		break;
	case Opt_perm:
		if (result.negated)
			ctx->noperm = 1;
		else
			ctx->noperm = 0;
		break;
	case Opt_dynperm:
		if (result.negated)
			ctx->dynperm = 0;
		else
			ctx->dynperm = 1;
		break;
	case Opt_sfu:
		if (result.negated)
			ctx->sfu_emul = 0;
		else
			ctx->sfu_emul = 1;
		break;
	case Opt_noblocksend:
		ctx->noblocksnd = 1;
		break;
	case Opt_noautotune:
		ctx->noautotune = 1;
		break;
	case Opt_nolease:
		ctx->no_lease = 1;
		break;
	case Opt_nosparse:
		ctx->no_sparse = 1;
		break;
	case Opt_nodelete:
		ctx->nodelete = 1;
		break;
	case Opt_multichannel:
		if (result.negated) {
			ctx->multichannel = false;
			ctx->max_channels = 1;
		} else {
			ctx->multichannel = true;
			/* if number of channels not specified, default to 2 */
			if (ctx->max_channels < 2)
				ctx->max_channels = 2;
		}
		break;
	case Opt_uid:
		uid = make_kuid(current_user_ns(), result.uint_32);
		if (!uid_valid(uid))
			goto cifs_parse_mount_err;
		ctx->linux_uid = uid;
		ctx->uid_specified = true;
		break;
	case Opt_cruid:
		uid = make_kuid(current_user_ns(), result.uint_32);
		if (!uid_valid(uid))
			goto cifs_parse_mount_err;
		ctx->cred_uid = uid;
		ctx->cruid_specified = true;
		break;
	case Opt_backupuid:
		uid = make_kuid(current_user_ns(), result.uint_32);
		if (!uid_valid(uid))
			goto cifs_parse_mount_err;
		ctx->backupuid = uid;
		ctx->backupuid_specified = true;
		break;
	case Opt_backupgid:
		gid = make_kgid(current_user_ns(), result.uint_32);
		if (!gid_valid(gid))
			goto cifs_parse_mount_err;
		ctx->backupgid = gid;
		ctx->backupgid_specified = true;
		break;
	case Opt_gid:
		gid = make_kgid(current_user_ns(), result.uint_32);
		if (!gid_valid(gid))
			goto cifs_parse_mount_err;
		ctx->linux_gid = gid;
		ctx->gid_specified = true;
		break;
	case Opt_port:
		ctx->port = result.uint_32;
		break;
	case Opt_file_mode:
		ctx->file_mode = result.uint_32;
		break;
	case Opt_dirmode:
		ctx->dir_mode = result.uint_32;
		break;
	case Opt_min_enc_offload:
		ctx->min_offload = result.uint_32;
		break;
	case Opt_blocksize:
		/*
		 * inode blocksize realistically should never need to be
		 * less than 16K or greater than 16M and default is 1MB.
		 * Note that small inode block sizes (e.g. 64K) can lead
		 * to very poor performance of common tools like cp and scp
		 */
		if ((result.uint_32 < CIFS_MAX_MSGSIZE) ||
		   (result.uint_32 > (4 * SMB3_DEFAULT_IOSIZE))) {
			cifs_errorf(fc, "%s: Invalid blocksize\n",
				__func__);
			goto cifs_parse_mount_err;
		}
		ctx->bsize = result.uint_32;
		ctx->got_bsize = true;
		break;
	case Opt_rasize:
		/*
		 * readahead size realistically should never need to be
		 * less than 1M (CIFS_DEFAULT_IOSIZE) or greater than 32M
		 * (perhaps an exception should be considered in the
		 * for the case of a large number of channels
		 * when multichannel is negotiated) since that would lead
		 * to plenty of parallel I/O in flight to the server.
		 * Note that smaller read ahead sizes would
		 * hurt performance of common tools like cp and scp
		 * which often trigger sequential i/o with read ahead
		 */
		if ((result.uint_32 > (8 * SMB3_DEFAULT_IOSIZE)) ||
		    (result.uint_32 < CIFS_DEFAULT_IOSIZE)) {
			cifs_errorf(fc, "%s: Invalid rasize %d vs. %d\n",
				__func__, result.uint_32, SMB3_DEFAULT_IOSIZE);
			goto cifs_parse_mount_err;
		}
		ctx->rasize = result.uint_32;
		break;
	case Opt_rsize:
		ctx->rsize = result.uint_32;
		ctx->got_rsize = true;
		break;
	case Opt_wsize:
		ctx->wsize = result.uint_32;
		ctx->got_wsize = true;
		break;
	case Opt_acregmax:
		ctx->acregmax = HZ * result.uint_32;
		if (ctx->acregmax > CIFS_MAX_ACTIMEO) {
			cifs_errorf(fc, "acregmax too large\n");
			goto cifs_parse_mount_err;
		}
		break;
	case Opt_acdirmax:
		ctx->acdirmax = HZ * result.uint_32;
		if (ctx->acdirmax > CIFS_MAX_ACTIMEO) {
			cifs_errorf(fc, "acdirmax too large\n");
			goto cifs_parse_mount_err;
		}
		break;
	case Opt_actimeo:
		if (HZ * result.uint_32 > CIFS_MAX_ACTIMEO) {
			cifs_errorf(fc, "timeout too large\n");
			goto cifs_parse_mount_err;
		}
		if ((ctx->acdirmax != CIFS_DEF_ACTIMEO) ||
		    (ctx->acregmax != CIFS_DEF_ACTIMEO)) {
			cifs_errorf(fc, "actimeo ignored since acregmax or acdirmax specified\n");
			break;
		}
		ctx->acdirmax = ctx->acregmax = HZ * result.uint_32;
		break;
	case Opt_closetimeo:
		ctx->closetimeo = HZ * result.uint_32;
		if (ctx->closetimeo > SMB3_MAX_DCLOSETIMEO) {
			cifs_errorf(fc, "closetimeo too large\n");
			goto cifs_parse_mount_err;
		}
		break;
	case Opt_echo_interval:
		ctx->echo_interval = result.uint_32;
		break;
	case Opt_snapshot:
		ctx->snapshot_time = result.uint_64;
		break;
	case Opt_max_credits:
		if (result.uint_32 < 20 || result.uint_32 > 60000) {
			cifs_errorf(fc, "%s: Invalid max_credits value\n",
				 __func__);
			goto cifs_parse_mount_err;
		}
		ctx->max_credits = result.uint_32;
		break;
	case Opt_max_channels:
		if (result.uint_32 < 1 || result.uint_32 > CIFS_MAX_CHANNELS) {
			cifs_errorf(fc, "%s: Invalid max_channels value, needs to be 1-%d\n",
				 __func__, CIFS_MAX_CHANNELS);
			goto cifs_parse_mount_err;
		}
		ctx->max_channels = result.uint_32;
		/* If more than one channel requested ... they want multichan */
		if (result.uint_32 > 1)
			ctx->multichannel = true;
		break;
	case Opt_handletimeout:
		ctx->handle_timeout = result.uint_32;
		if (ctx->handle_timeout > SMB3_MAX_HANDLE_TIMEOUT) {
			cifs_errorf(fc, "Invalid handle cache timeout, longer than 16 minutes\n");
			goto cifs_parse_mount_err;
		}
		break;
	case Opt_source:
		kfree(ctx->UNC);
		ctx->UNC = NULL;
		switch ((*klpe_smb3_parse_devname)(param->string, ctx)) {
		case 0:
			break;
		case -ENOMEM:
			cifs_errorf(fc, "Unable to allocate memory for devname\n");
			goto cifs_parse_mount_err;
		case -EINVAL:
			cifs_errorf(fc, "Malformed UNC in devname\n");
			goto cifs_parse_mount_err;
		default:
			cifs_errorf(fc, "Unknown error parsing devname\n");
			goto cifs_parse_mount_err;
		}
		ctx->source = (*klpe_smb3_fs_context_fullpath)(ctx, '/');
		if (IS_ERR(ctx->source)) {
			ctx->source = NULL;
			cifs_errorf(fc, "OOM when copying UNC string\n");
			goto cifs_parse_mount_err;
		}
		fc->source = kstrdup(ctx->source, GFP_KERNEL);
		if (fc->source == NULL) {
			cifs_errorf(fc, "OOM when copying UNC string\n");
			goto cifs_parse_mount_err;
		}
		break;
	case Opt_user:
		kfree(ctx->username);
		ctx->username = NULL;
		if (ctx->nullauth)
			break;
		if (strlen(param->string) == 0) {
			/* null user, ie. anonymous authentication */
			ctx->nullauth = 1;
			break;
		}

		if (strnlen(param->string, CIFS_MAX_USERNAME_LEN) >
		    CIFS_MAX_USERNAME_LEN) {
			pr_warn("username too long\n");
			goto cifs_parse_mount_err;
		}
		ctx->username = kstrdup(param->string, GFP_KERNEL);
		if (ctx->username == NULL) {
			cifs_errorf(fc, "OOM when copying username string\n");
			goto cifs_parse_mount_err;
		}
		break;
	case Opt_pass:
		kfree_sensitive(ctx->password);
		ctx->password = NULL;
		if (strlen(param->string) == 0)
			break;

		ctx->password = kstrdup(param->string, GFP_KERNEL);
		if (ctx->password == NULL) {
			cifs_errorf(fc, "OOM when copying password string\n");
			goto cifs_parse_mount_err;
		}
		break;
	case Opt_ip:
		if (strlen(param->string) == 0) {
			ctx->got_ip = false;
			break;
		}
		if (!(*klpe_cifs_convert_address)((struct sockaddr *)&ctx->dstaddr,
					  param->string,
					  strlen(param->string))) {
			pr_err("bad ip= option (%s)\n", param->string);
			goto cifs_parse_mount_err;
		}
		ctx->got_ip = true;
		break;
	case Opt_domain:
		if (strnlen(param->string, CIFS_MAX_DOMAINNAME_LEN)
				== CIFS_MAX_DOMAINNAME_LEN) {
			pr_warn("domain name too long\n");
			goto cifs_parse_mount_err;
		}

		kfree(ctx->domainname);
		ctx->domainname = kstrdup(param->string, GFP_KERNEL);
		if (ctx->domainname == NULL) {
			cifs_errorf(fc, "OOM when copying domainname string\n");
			goto cifs_parse_mount_err;
		}
		cifs_dbg(FYI, "Domain name set\n");
		break;
	case Opt_srcaddr:
		if (!(*klpe_cifs_convert_address)(
				(struct sockaddr *)&ctx->srcaddr,
				param->string, strlen(param->string))) {
			pr_warn("Could not parse srcaddr: %s\n",
				param->string);
			goto cifs_parse_mount_err;
		}
		break;
	case Opt_iocharset:
		if (strnlen(param->string, 1024) >= 65) {
			pr_warn("iocharset name too long\n");
			goto cifs_parse_mount_err;
		}

		if (strncasecmp(param->string, "default", 7) != 0) {
			kfree(ctx->iocharset);
			ctx->iocharset = kstrdup(param->string, GFP_KERNEL);
			if (ctx->iocharset == NULL) {
				cifs_errorf(fc, "OOM when copying iocharset string\n");
				goto cifs_parse_mount_err;
			}
		}
		/* if iocharset not set then load_nls_default
		 * is used by caller
		 */
		cifs_dbg(FYI, "iocharset set to %s\n", ctx->iocharset);
		break;
	case Opt_netbiosname:
		memset(ctx->source_rfc1001_name, 0x20,
			RFC1001_NAME_LEN);
		/*
		 * FIXME: are there cases in which a comma can
		 * be valid in workstation netbios name (and
		 * need special handling)?
		 */
		for (i = 0; i < RFC1001_NAME_LEN; i++) {
			/* don't ucase netbiosname for user */
			if (param->string[i] == 0)
				break;
			ctx->source_rfc1001_name[i] = param->string[i];
		}
		/* The string has 16th byte zero still from
		 * set at top of the function
		 */
		if (i == RFC1001_NAME_LEN && param->string[i] != 0)
			pr_warn("netbiosname longer than 15 truncated\n");
		break;
	case Opt_servern:
		/* last byte, type, is 0x20 for servr type */
		memset(ctx->target_rfc1001_name, 0x20,
			RFC1001_NAME_LEN_WITH_NULL);
		/*
		 * BB are there cases in which a comma can be valid in this
		 * workstation netbios name (and need special handling)?
		 */

		/* user or mount helper must uppercase the netbios name */
		for (i = 0; i < 15; i++) {
			if (param->string[i] == 0)
				break;
			ctx->target_rfc1001_name[i] = param->string[i];
		}

		/* The string has 16th byte zero still from set at top of function */
		if (i == RFC1001_NAME_LEN && param->string[i] != 0)
			pr_warn("server netbiosname longer than 15 truncated\n");
		break;
	case Opt_ver:
		/* version of mount userspace tools, not dialect */
		/* If interface changes in mount.cifs bump to new ver */
		if (strncasecmp(param->string, "1", 1) == 0) {
			if (strlen(param->string) > 1) {
				pr_warn("Bad mount helper ver=%s. Did you want SMB1 (CIFS) dialect and mean to type vers=1.0 instead?\n",
					param->string);
				goto cifs_parse_mount_err;
			}
			/* This is the default */
			break;
		}
		/* For all other value, error */
		pr_warn("Invalid mount helper version specified\n");
		goto cifs_parse_mount_err;
	case Opt_vers:
		/* protocol version (dialect) */
		if (klpr_cifs_parse_smb_version(fc, param->string, ctx, is_smb3) != 0)
			goto cifs_parse_mount_err;
		ctx->got_version = true;
		break;
	case Opt_sec:
		if (klpr_cifs_parse_security_flavors(fc, param->string, ctx) != 0)
			goto cifs_parse_mount_err;
		break;
	case Opt_cache:
		if (klpr_cifs_parse_cache_flavor(fc, param->string, ctx) != 0)
			goto cifs_parse_mount_err;
		break;
	case Opt_witness:
#ifndef CONFIG_CIFS_SWN_UPCALL
#error "klp-ccp: non-taken branch"
#endif
		ctx->witness = true;
		pr_warn_once("Witness protocol support is experimental\n");
		break;
	case Opt_rootfs:
#ifndef CONFIG_CIFS_ROOT
		cifs_dbg(VFS, "rootfs support requires CONFIG_CIFS_ROOT config option\n");
		goto cifs_parse_mount_err;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		ctx->rootfs = true;
		break;
	case Opt_posixpaths:
		if (result.negated)
			ctx->posix_paths = 0;
		else
			ctx->posix_paths = 1;
		break;
	case Opt_unix:
		if (result.negated) {
			if (ctx->linux_ext == 1)
				pr_warn_once("conflicting posix mount options specified\n");
			ctx->linux_ext = 0;
			ctx->no_linux_ext = 1;
		} else {
			if (ctx->no_linux_ext == 1)
				pr_warn_once("conflicting posix mount options specified\n");
			ctx->linux_ext = 1;
			ctx->no_linux_ext = 0;
		}
		break;
	case Opt_nocase:
		ctx->nocase = 1;
		break;
	case Opt_brl:
		if (result.negated) {
			/*
			 * turn off mandatory locking in mode
			 * if remote locking is turned off since the
			 * local vfs will do advisory
			 */
			if (ctx->file_mode ==
				(S_IALLUGO & ~(S_ISUID | S_IXGRP)))
				ctx->file_mode = S_IALLUGO;
			ctx->nobrl =  1;
		} else
			ctx->nobrl =  0;
		break;
	case Opt_handlecache:
		if (result.negated)
			ctx->nohandlecache = 1;
		else
			ctx->nohandlecache = 0;
		break;
	case Opt_forcemandatorylock:
		ctx->mand_lock = 1;
		break;
	case Opt_setuids:
		ctx->setuids = result.negated;
		break;
	case Opt_intr:
		ctx->intr = !result.negated;
		break;
	case Opt_setuidfromacl:
		ctx->setuidfromacl = 1;
		break;
	case Opt_strictsync:
		ctx->nostrictsync = result.negated;
		break;
	case Opt_serverino:
		ctx->server_ino = !result.negated;
		break;
	case Opt_rwpidforward:
		ctx->rwpidforward = 1;
		break;
	case Opt_modesid:
		ctx->mode_ace = 1;
		break;
	case Opt_cifsacl:
		ctx->cifs_acl = !result.negated;
		break;
	case Opt_acl:
		ctx->no_psx_acl = result.negated;
		break;
	case Opt_locallease:
		ctx->local_lease = 1;
		break;
	case Opt_sign:
		ctx->sign = true;
		break;
	case Opt_ignore_signature:
		ctx->sign = true;
		ctx->ignore_signature = true;
		break;
	case Opt_seal:
		/* we do not do the following in secFlags because seal
		 * is a per tree connection (mount) not a per socket
		 * or per-smb connection option in the protocol
		 * vol->secFlg |= CIFSSEC_MUST_SEAL;
		 */
		ctx->seal = 1;
		break;
	case Opt_noac:
		pr_warn("Mount option noac not supported. Instead set /proc/fs/cifs/LookupCacheEnabled to 0\n");
		break;
	case Opt_fsc:
#ifndef CONFIG_CIFS_FSCACHE
#error "klp-ccp: non-taken branch"
#endif
		ctx->fsc = true;
		break;
	case Opt_mfsymlinks:
		ctx->mfsymlinks = true;
		break;
	case Opt_multiuser:
		ctx->multiuser = true;
		break;
	case Opt_sloppy:
		ctx->sloppy = true;
		break;
	case Opt_nosharesock:
		ctx->nosharesock = true;
		break;
	case Opt_persistent:
		if (result.negated) {
			ctx->nopersistent = true;
			if (ctx->persistent) {
				cifs_errorf(fc, "persistenthandles mount options conflict\n");
				goto cifs_parse_mount_err;
			}
		} else {
			ctx->persistent = true;
			if ((ctx->nopersistent) || (ctx->resilient)) {
				cifs_errorf(fc, "persistenthandles mount options conflict\n");
				goto cifs_parse_mount_err;
			}
		}
		break;
	case Opt_resilient:
		if (result.negated) {
			ctx->resilient = false; /* already the default */
		} else {
			ctx->resilient = true;
			if (ctx->persistent) {
				cifs_errorf(fc, "persistenthandles mount options conflict\n");
				goto cifs_parse_mount_err;
			}
		}
		break;
	case Opt_tcp_nodelay:
		/* tcp nodelay should not usually be needed since we CORK/UNCORK the socket */
		if (result.negated)
			ctx->sockopt_tcp_nodelay = false;
		else
			ctx->sockopt_tcp_nodelay = true;
		break;
	case Opt_domainauto:
		ctx->domainauto = true;
		break;
	case Opt_rdma:
		ctx->rdma = true;
		break;
	}
	/* case Opt_ignore: - is ignored as expected ... */

	return 0;

 cifs_parse_mount_err:
	kfree_sensitive(ctx->password);
	ctx->password = NULL;
	return -EINVAL;
}



#include "livepatch_bsc1215971.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "cifs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "cifsFYI", (void *)&klpe_cifsFYI, "cifs" },
	{ "cifs_cacheflavor_tokens", (void *)&klpe_cifs_cacheflavor_tokens,
	  "cifs" },
	{ "cifs_convert_address", (void *)&klpe_cifs_convert_address, "cifs" },
	{ "cifs_secflavor_tokens", (void *)&klpe_cifs_secflavor_tokens,
	  "cifs" },
	{ "cifs_smb_version_tokens", (void *)&klpe_cifs_smb_version_tokens,
	  "cifs" },
	{ "disable_legacy_dialects", (void *)&klpe_disable_legacy_dialects,
	  "cifs" },
	{ "smb1_operations", (void *)&klpe_smb1_operations, "cifs" },
	{ "smb1_values", (void *)&klpe_smb1_values, "cifs" },
	{ "smb20_operations", (void *)&klpe_smb20_operations, "cifs" },
	{ "smb20_values", (void *)&klpe_smb20_values, "cifs" },
	{ "smb21_operations", (void *)&klpe_smb21_operations, "cifs" },
	{ "smb21_values", (void *)&klpe_smb21_values, "cifs" },
	{ "smb302_values", (void *)&klpe_smb302_values, "cifs" },
	{ "smb30_operations", (void *)&klpe_smb30_operations, "cifs" },
	{ "smb30_values", (void *)&klpe_smb30_values, "cifs" },
	{ "smb311_operations", (void *)&klpe_smb311_operations, "cifs" },
	{ "smb311_values", (void *)&klpe_smb311_values, "cifs" },
	{ "smb3_fs_context_fullpath", (void *)&klpe_smb3_fs_context_fullpath,
	  "cifs" },
	{ "smb3_fs_parameters", (void *)&klpe_smb3_fs_parameters, "cifs" },
	{ "smb3_parse_devname", (void *)&klpe_smb3_parse_devname, "cifs" },
	{ "smb3any_values", (void *)&klpe_smb3any_values, "cifs" },
	{ "smbdefault_values", (void *)&klpe_smbdefault_values, "cifs" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1215971_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1215971_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
