/*
 * livepatch_bsc1225819
 *
 * Fix for CVE-2023-52752, bsc#1225819
 *
 *  Upstream commit:
 *  d328c09ee9f1 ("smb: client: fix use-after-free bug in cifs_debug_data_proc_show()")
 *
 *  SLE12-SP5 commit:
 *  b2bff1743ca39bcf80a6fdce81bc7e0596e83d65
 *
 *  SLE15-SP2 and -SP3 commit:
 *  c058f4eb5f62e17d355e4c15568ce91dc2fb80c1
 *
 *  SLE15-SP4 and -SP5 commit:
 *  39fb8f3bfaf5e9b5e77bf704abad4599c30747e3
 *
 *  SLE15-SP6 commit:
 *  c4e1b53b8eddd5be026a1921f301ebdb080191b9
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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


/* klp-ccp: from fs/smb/client/cifs_debug.c */
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <uapi/linux/ethtool.h>
/* klp-ccp: from fs/smb/client/cifspdu.h */
#include <net/sock.h>

#define CIFS_CRYPTO_KEY_SIZE (8)

typedef struct {
	__le16 MajorVersionNumber;
	__le16 MinorVersionNumber;
	__le64 Capability;
} __attribute__((packed)) FILE_SYSTEM_UNIX_INFO;

typedef struct {
	__le32 DeviceType;
	__le32 DeviceCharacteristics;
} __attribute__((packed)) FILE_SYSTEM_DEVICE_INFO;

typedef struct {
	__le32 Attributes;
	__le32 MaxPathNameComponentLength;
	__le32 FileSystemNameLen;
	char FileSystemName[52]; /* do not have to save this - get subset? */
} __attribute__((packed)) FILE_SYSTEM_ATTRIBUTE_INFO;

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

#define INET6_ADDRSTRLEN	(48)

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
#define NUMBER_OF_SMB2_COMMANDS	0x0013

#define SMB3_ENC_DEC_KEY_SIZE		32

#define SMB3_SIGN_KEY_SIZE		16

#define SMB2_CLIENT_GUID_SIZE		16

#define SMB2_PREAUTH_HASH_SIZE 64

#define SMB2_ENCRYPTION_AES256_GCM      cpu_to_le16(0x0004)

#define SMB3_COMPRESS_LZNT1	cpu_to_le16(0x0001)
#define SMB3_COMPRESS_LZ77	cpu_to_le16(0x0002)
#define SMB3_COMPRESS_LZ77_HUFF	cpu_to_le16(0x0003)

#define SMB2_SESSION_FLAG_IS_GUEST        0x0001

#define SMB2_SESSION_FLAG_IS_NULL         0x0002

#define SMB2_SESSION_FLAG_ENCRYPT_DATA    0x0004

/* klp-ccp: from fs/smb/client/smb2pdu.h */
#include <net/sock.h>

/* klp-ccp: from fs/smb/client/cifsglob.h */
#define MAX_TREE_SIZE (2 + CIFS_NI_MAXHOST + 1 + CIFS_MAX_SHARE_LEN + 1)

#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

#define CIFS_MAX_WORKSTATION_LEN  (__NEW_UTS_LEN + 1)  /* reasonable max for client */

enum statusEnum {
	CifsNew = 0,
	CifsGood,
	CifsExiting,
	CifsNeedReconnect,
	CifsNeedNegotiate,
	CifsInNegotiate,
};

enum ses_status_enum {
	SES_NEW = 0,
	SES_GOOD,
	SES_EXITING,
	SES_NEED_RECON,
	SES_IN_SETUP
};

enum tid_status_enum {
	TID_NEW = 0,
	TID_GOOD,
	TID_EXITING,
	TID_NEED_RECON,
	TID_NEED_TCON,
	TID_IN_TCON,
	TID_NEED_FILES_INVALIDATE, /* currently unused */
	TID_IN_FILES_INVALIDATE
};

enum securityEnum {
	Unspecified = 0,	/* not specified */
	NTLMv2,			/* Legacy NTLM auth with NTLMv2 hash */
	RawNTLMSSP,		/* NTLMSSP without SPNEGO, NTLMv2 hash */
	Kerberos,		/* Kerberos via SPNEGO */
};

struct session_key {
	unsigned int len;
	char *response;
};

struct cifs_secmech {
	struct shash_desc *hmacmd5; /* hmacmd5 hash function, for NTLMv2/CR1 hashes */
	struct shash_desc *md5; /* md5 hash function, for CIFS/SMB1 signatures */
	struct shash_desc *hmacsha256; /* hmac-sha256 hash function, for SMB2 signatures */
	struct shash_desc *sha512; /* sha512 hash function, for SMB3.1.1 preauth hash */
	struct shash_desc *aes_cmac; /* block-cipher based MAC function, for SMB3 signatures */

	struct crypto_aead *enc; /* smb3 encryption AEAD TFM (AES-CCM and AES-GCM) */
	struct crypto_aead *dec; /* smb3 decryption AEAD TFM (AES-CCM and AES-GCM) */
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

struct TCP_Server_Info {
	struct list_head tcp_ses_list;
	struct list_head smb_ses_list;
	spinlock_t srv_lock;  /* protect anything here that is not protected */
	__u64 conn_id; /* connection identifier (useful for debugging) */
	int srv_count; /* reference counter */
	/* 15 character server name + 0x20 16th byte indicating type = srv */
	char server_RFC1001_name[RFC1001_NAME_LEN_WITH_NULL];
	struct smb_version_operations	*ops;
	struct smb_version_values	*vals;
	/* updates to tcpStatus protected by cifs_tcp_ses_lock */
	enum statusEnum tcpStatus; /* what we think the status is */
	char *hostname; /* hostname portion of UNC string */
	struct socket *ssocket;
	struct sockaddr_storage dstaddr;
	struct sockaddr_storage srcaddr; /* locally bind to this IP */
#ifdef CONFIG_NET_NS
	struct net *net;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	wait_queue_head_t response_q;
	wait_queue_head_t request_q; /* if more than maxmpx to srvr must block*/
	spinlock_t mid_lock;  /* protect mid queue and it's entries */
	struct list_head pending_mid_q;
	bool noblocksnd;		/* use blocking sendmsg */
	bool noautotune;		/* do not autotune send buf sizes */
	bool nosharesock;
	bool tcp_nodelay;
	unsigned int credits;  /* send no more requests at once */
	unsigned int max_credits; /* can override large 32000 default at mnt */
	unsigned int in_flight;  /* number of requests on the wire to server */
	unsigned int max_in_flight; /* max number of requests that were on wire */
	spinlock_t req_lock;  /* protect the two values above */
	struct mutex _srv_mutex;
	unsigned int nofs_flag;
	struct task_struct *tsk;
	char server_GUID[16];
	__u16 sec_mode;
	bool sign; /* is signing enabled on this connection? */
	bool ignore_signature:1; /* skip validation of signatures in SMB2/3 rsp */
	bool session_estab; /* mark when very first sess is established */
	int echo_credits;  /* echo reserved slots */
	int oplock_credits;  /* oplock break reserved slots */
	bool echoes:1; /* enable echoes */
	__u8 client_guid[SMB2_CLIENT_GUID_SIZE]; /* Client GUID */
	u16 dialect; /* dialect index that server chose */
	bool oplocks:1; /* enable oplocks */
	unsigned int maxReq;	/* Clients should submit no more */
	/* than maxReq distinct unanswered SMBs to the server when using  */
	/* multiplexed reads or writes (for SMB1/CIFS only, not SMB2/SMB3) */
	unsigned int maxBuf;	/* maxBuf specifies the maximum */
	/* message size the server can send or receive for non-raw SMBs */
	/* maxBuf is returned by SMB NegotiateProtocol so maxBuf is only 0 */
	/* when socket is setup (and during reconnect) before NegProt sent */
	unsigned int max_rw;	/* maxRw specifies the maximum */
	/* message size the server can send or receive for */
	/* SMB_COM_WRITE_RAW or SMB_COM_READ_RAW. */
	unsigned int capabilities; /* selective disabling of caps by smb sess */
	int timeAdj;  /* Adjust for difference in server time zone in sec */
	__u64 CurrentMid;         /* multiplex id - rotating counter, protected by GlobalMid_Lock */
	char cryptkey[CIFS_CRYPTO_KEY_SIZE]; /* used by ntlm, ntlmv2 etc */
	/* 16th byte of RFC1001 workstation name is always null */
	char workstation_RFC1001_name[RFC1001_NAME_LEN_WITH_NULL];
	__u32 sequence_number; /* for signing, protected by srv_mutex */
	__u32 reconnect_instance; /* incremented on each reconnect */
	struct session_key session_key;
	unsigned long lstrp; /* when we got last response from this server */
	struct cifs_secmech secmech; /* crypto sec mech functs, descriptors */
	char	negflavor;	/* NEGOTIATE response flavor */
	/* extended security flavors that server supports */
	bool	sec_ntlmssp;		/* supports NTLMSSP */
	bool	sec_kerberosu2u;	/* supports U2U Kerberos */
	bool	sec_kerberos;		/* supports plain Kerberos */
	bool	sec_mskerberos;		/* supports legacy MS Kerberos */
	bool	large_buf;		/* is current buffer large? */
	/* use SMBD connection instead of socket */
	bool	rdma;
	/* point to the SMBD connection if RDMA is used instead of socket */
	struct smbd_connection *smbd_conn;
	struct delayed_work	echo; /* echo ping workqueue job */
	char	*smallbuf;	/* pointer to current "small" buffer */
	char	*bigbuf;	/* pointer to current "big" buffer */
	/* Total size of this PDU. Only valid from cifs_demultiplex_thread */
	unsigned int pdu_size;
	unsigned int total_read; /* total amount of data read in this pass */
	atomic_t in_send; /* requests trying to send */
	atomic_t num_waiters;   /* blocked waiting to get in sendrecv */
#ifdef CONFIG_CIFS_STATS2
	atomic_t num_cmds[NUMBER_OF_SMB2_COMMANDS]; /* total requests by cmd */
	atomic_t smb2slowcmd[NUMBER_OF_SMB2_COMMANDS]; /* count resps > 1 sec */
	__u64 time_per_cmd[NUMBER_OF_SMB2_COMMANDS]; /* total time per cmd */
	__u32 slowest_cmd[NUMBER_OF_SMB2_COMMANDS];
	__u32 fastest_cmd[NUMBER_OF_SMB2_COMMANDS];
#endif /* STATS2 */
	unsigned int	max_read;
	unsigned int	max_write;
	unsigned int	min_offload;
	__le16	compress_algorithm;
	__u16	signing_algorithm;
	__le16	cipher_type;
	 /* save initital negprot hash */
	__u8	preauth_sha_hash[SMB2_PREAUTH_HASH_SIZE];
	bool	signing_negotiated; /* true if valid signing context rcvd from server */
	bool	posix_ext_supported;
	struct delayed_work reconnect; /* reconnect workqueue job */
	struct mutex reconnect_mutex; /* prevent simultaneous reconnects */
	unsigned long echo_interval;

	/*
	 * Number of targets available for reconnect. The more targets
	 * the more tasks have to wait to let the demultiplex thread
	 * reconnect.
	 */
	int nr_targets;
	bool noblockcnt; /* use non-blocking connect() */

#define CIFS_SERVER_IS_CHAN(server)	(!!(server)->primary_server)
	struct TCP_Server_Info *primary_server;

#ifdef CONFIG_CIFS_SWN_UPCALL
	bool use_swn_dstaddr;
	struct sockaddr_storage swn_dstaddr;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct mutex refpath_lock; /* protects leaf_fullpath */
	/*
	 * leaf_fullpath: Canonical DFS referral path related to this
	 *                connection.
	 *                It is used in DFS cache refresher, reconnect and may
	 *                change due to nested DFS links.
	 *
	 * Protected by @refpath_lock and @srv_lock.  The @refpath_lock is
	 * mostly used for not requiring a copy of @leaf_fullpath when getting
	 * cached or new DFS referrals (which might also sleep during I/O).
	 * While @srv_lock is held for making string and NULL comparions against
	 * both fields as in mount(2) and cache refresh.
	 *
	 * format: \\HOST\SHARE[\OPTIONAL PATH]
	 */
	char *leaf_fullpath;
};

static inline unsigned int
in_flight(struct TCP_Server_Info *server)
{
	unsigned int num;

	spin_lock(&server->req_lock);
	num = server->in_flight;
	spin_unlock(&server->req_lock);
	return num;
}

struct cifs_server_iface {
	struct list_head iface_head;
	struct kref refcount;
	size_t speed;
	unsigned int rdma_capable : 1;
	unsigned int rss_capable : 1;
	unsigned int is_active : 1; /* unset if non existent */
	struct sockaddr_storage sockaddr;
};

struct cifs_chan {
	unsigned int in_reconnect : 1; /* if session setup in progress for this channel */
	struct TCP_Server_Info *server;
	struct cifs_server_iface *iface; /* interface in use */
	__u8 signkey[SMB3_SIGN_KEY_SIZE];
};

struct cifs_ses {
	struct list_head smb_ses_list;
	struct list_head rlist; /* reconnect list */
	struct list_head tcon_list;
	struct cifs_tcon *tcon_ipc;
	spinlock_t ses_lock;  /* protect anything here that is not protected */
	struct mutex session_mutex;
	struct TCP_Server_Info *server;	/* pointer to server info */
	int ses_count;		/* reference counter */
	enum ses_status_enum ses_status;  /* updates protected by cifs_tcp_ses_lock */
	unsigned int overrideSecFlg; /* if non-zero override global sec flags */
	char *serverOS;		/* name of operating system underlying server */
	char *serverNOS;	/* name of network operating system of server */
	char *serverDomain;	/* security realm of server */
	__u64 Suid;		/* remote smb uid  */
	kuid_t linux_uid;	/* overriding owner of files on the mount */
	kuid_t cred_uid;	/* owner of credentials */
	unsigned int capabilities;
	char ip_addr[INET6_ADDRSTRLEN + 1]; /* Max ipv6 (or v4) addr string len */
	char *user_name;	/* must not be null except during init of sess
				   and after mount option parsing we fill it */
	char *domainName;
	char *password;
	char workstation_name[CIFS_MAX_WORKSTATION_LEN];
	struct session_key auth_key;
	struct ntlmssp_auth *ntlmssp; /* ciphertext, flags, server challenge */
	enum securityEnum sectype; /* what security flavor was specified? */
	bool sign;		/* is signing required? */
	bool domainAuto:1;
	__u16 session_flags;
	__u8 smb3signingkey[SMB3_SIGN_KEY_SIZE];
	__u8 smb3encryptionkey[SMB3_ENC_DEC_KEY_SIZE];
	__u8 smb3decryptionkey[SMB3_ENC_DEC_KEY_SIZE];
	__u8 preauth_sha_hash[SMB2_PREAUTH_HASH_SIZE];

	/*
	 * Network interfaces available on the server this session is
	 * connected to.
	 *
	 * Other channels can be opened by connecting and binding this
	 * session to interfaces from this list.
	 *
	 * iface_lock should be taken when accessing any of these fields
	 */
	spinlock_t iface_lock;
	/* ========= begin: protected by iface_lock ======== */
	struct list_head iface_list;
	size_t iface_count;
	unsigned long iface_last_update; /* jiffies */
	/* ========= end: protected by iface_lock ======== */

	spinlock_t chan_lock;

#define CIFS_MAX_CHANNELS 16

#define CIFS_CHAN_NEEDS_RECONNECT(ses, index)	\
	test_bit((index), &(ses)->chans_need_reconnect)
#define CIFS_CHAN_IN_RECONNECT(ses, index)	\
	((ses)->chans[(index)].in_reconnect)
	struct cifs_chan chans[CIFS_MAX_CHANNELS];
	size_t chan_count;
	size_t chan_max;
	atomic_t chan_seq; /* round robin state */

	/*
	 * chans_need_reconnect is a bitmap indicating which of the channels
	 * under this smb session needs to be reconnected.
	 * If not multichannel session, only one bit will be used.
	 *
	 * We will ask for sess and tcon reconnection only if all the
	 * channels are marked for needing reconnection. This will
	 * enable the sessions on top to continue to live till any
	 * of the channels below are active.
	 */
	unsigned long chans_need_reconnect;
	/* ========= end: protected by chan_lock ======== */
	struct cifs_ses *dfs_root_ses;
};

struct cifs_tcon {
	struct list_head tcon_list;
	int tc_count;
	struct list_head rlist; /* reconnect list */
	spinlock_t tc_lock;  /* protect anything here that is not protected */
	atomic_t num_local_opens;  /* num of all opens including disconnected */
	atomic_t num_remote_opens; /* num of all network opens on server */
	struct list_head openFileList;
	spinlock_t open_file_lock; /* protects list above */
	struct cifs_ses *ses;	/* pointer to session associated with */
	char tree_name[MAX_TREE_SIZE + 1]; /* UNC name of resource in ASCII */
	char *nativeFileSystem;
	char *password;		/* for share-level security */
	__u32 tid;		/* The 4 byte tree id */
	__u16 Flags;		/* optional support bits */
	enum tid_status_enum status;
	atomic_t num_smbs_sent;
	union {
		struct {
			atomic_t num_writes;
			atomic_t num_reads;
			atomic_t num_flushes;
			atomic_t num_oplock_brks;
			atomic_t num_opens;
			atomic_t num_closes;
			atomic_t num_deletes;
			atomic_t num_mkdirs;
			atomic_t num_posixopens;
			atomic_t num_posixmkdirs;
			atomic_t num_rmdirs;
			atomic_t num_renames;
			atomic_t num_t2renames;
			atomic_t num_ffirst;
			atomic_t num_fnext;
			atomic_t num_fclose;
			atomic_t num_hardlinks;
			atomic_t num_symlinks;
			atomic_t num_locks;
			atomic_t num_acl_get;
			atomic_t num_acl_set;
		} cifs_stats;
		struct {
			atomic_t smb2_com_sent[NUMBER_OF_SMB2_COMMANDS];
			atomic_t smb2_com_failed[NUMBER_OF_SMB2_COMMANDS];
		} smb2_stats;
	} stats;
	__u64    bytes_read;
	__u64    bytes_written;
	spinlock_t stat_lock;  /* protects the two fields above */
	FILE_SYSTEM_DEVICE_INFO fsDevInfo;
	FILE_SYSTEM_ATTRIBUTE_INFO fsAttrInfo; /* ok if fs name truncated */
	FILE_SYSTEM_UNIX_INFO fsUnixInfo;
	bool ipc:1;   /* set if connection to IPC$ share (always also pipe) */
	bool pipe:1;  /* set if connection to pipe share */
	bool print:1; /* set if connection to printer share */
	bool retry:1;
	bool nocase:1;
	bool nohandlecache:1; /* if strange server resource prob can turn off */
	bool nodelete:1;
	bool seal:1;      /* transport encryption for this mounted share */
	bool unix_ext:1;  /* if false disable Linux extensions to CIFS protocol
				for this mount even if server would support */
	bool posix_extensions; /* if true SMB3.11 posix extensions enabled */
	bool local_lease:1; /* check leases (only) on local system not remote */
	bool broken_posix_open; /* e.g. Samba server versions < 3.3.2, 3.2.9 */
	bool broken_sparse_sup; /* if server or share does not support sparse */
	bool need_reconnect:1; /* connection reset, tid now invalid */
	bool need_reopen_files:1; /* need to reopen tcon file handles */
	bool use_resilient:1; /* use resilient instead of durable handles */
	bool use_persistent:1; /* use persistent instead of durable handles */
	bool no_lease:1;    /* Do not request leases on files or directories */
	bool use_witness:1; /* use witness protocol */
	__le32 capabilities;
	__u32 share_flags;
	__u32 maximal_access;
	__u32 vol_serial_number;
	__le64 vol_create_time;
	__u64 snapshot_time; /* for timewarp tokens - timestamp of snapshot */
	__u32 handle_timeout; /* persistent and durable handle timeout in ms */
	__u32 ss_flags;		/* sector size flags */
	__u32 perf_sector_size; /* best sector size for perf */
	__u32 max_chunks;
	__u32 max_bytes_chunk;
	__u32 max_bytes_copy;
#ifdef CONFIG_CIFS_FSCACHE
	u64 resource_id;		/* server resource id */
	struct fscache_volume *fscache;	/* cookie for share */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct list_head pending_opens;	/* list of incomplete opens */
	struct cached_fids *cfids;

#ifdef CONFIG_CIFS_DFS_UPCALL
	struct list_head dfs_ses_list;
	struct delayed_work dfs_cache_work;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct delayed_work	query_interfaces; /* query interfaces workqueue job */
	char *origin_fullpath; /* canonical copy of smb3_fs_context::source */
};

typedef int (mid_receive_t)(struct TCP_Server_Info *server,
			    struct mid_q_entry *mid);

typedef void (mid_callback_t)(struct mid_q_entry *mid);

typedef int (mid_handle_t)(struct TCP_Server_Info *server,
			    struct mid_q_entry *mid);

struct mid_q_entry {
	struct list_head qhead;	/* mids waiting on reply from this server */
	struct kref refcount;
	struct TCP_Server_Info *server;	/* server corresponding to this mid */
	__u64 mid;		/* multiplex id */
	__u16 credits;		/* number of credits consumed by this mid */
	__u16 credits_received;	/* number of credits from the response */
	__u32 pid;		/* process id */
	__u32 sequence_number;  /* for CIFS signing */
	unsigned long when_alloc;  /* when mid was created */
#ifdef CONFIG_CIFS_STATS2
	unsigned long when_sent; /* time when smb send finished */
	unsigned long when_received; /* when demux complete (taken off wire) */
#endif
	mid_receive_t *receive; /* call receive callback */
	mid_callback_t *callback; /* call completion callback */
	mid_handle_t *handle; /* call handle mid callback */
	void *callback_data;	  /* general purpose pointer for callback */
	struct task_struct *creator;
	void *resp_buf;		/* pointer to received SMB header */
	unsigned int resp_buf_size;
	int mid_state;	/* wish this were enum but can not pass to wait_event */
	unsigned int mid_flags;
	__le16 command;		/* smb command code */
	unsigned int optype;	/* operation type */
	bool large_buf:1;	/* if valid response, is pointer to large buf */
	bool multiRsp:1;	/* multiple trans2 responses for one request  */
	bool multiEnd:1;	/* both received */
	bool decrypted:1;	/* decrypted entry */
};

extern struct list_head		cifs_tcp_ses_list;

extern spinlock_t		cifs_tcp_ses_lock;

extern unsigned int GlobalTotalActiveXid;

extern unsigned int CIFSMaxBufSize;

static inline char *get_security_type_str(enum securityEnum sectype)
{
	switch (sectype) {
	case RawNTLMSSP:
		return "RawNTLMSSP";
	case Kerberos:
		return "Kerberos";
	case NTLMv2:
		return "NTLMv2";
	default:
		return "Unknown";
	}
}

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

bool is_ses_using_iface(struct cifs_ses *ses, struct cifs_server_iface *iface);

/* klp-ccp: from fs/smb/client/cifsfs.h */
#include <linux/hash.h>

#define CIFS_VERSION   "2.44"

/* klp-ccp: from fs/smb/client/cifs_swn.h */
#ifdef CONFIG_CIFS_SWN_UPCALL

extern void cifs_swn_dump(struct seq_file *m);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_CIFS_SWN_UPCALL */

/* klp-ccp: from fs/smb/client/cifs_debug.c */
#ifdef CONFIG_PROC_FS
extern void cifs_debug_tcon(struct seq_file *m, struct cifs_tcon *tcon);

static void
cifs_dump_channel(struct seq_file *m, int i, struct cifs_chan *chan)
{
	struct TCP_Server_Info *server = chan->server;

	seq_printf(m, "\n\n\t\tChannel: %d ConnectionId: 0x%llx"
		   "\n\t\tNumber of credits: %d,%d,%d Dialect 0x%x"
		   "\n\t\tTCP status: %d Instance: %d"
		   "\n\t\tLocal Users To Server: %d SecMode: 0x%x Req On Wire: %d"
		   "\n\t\tIn Send: %d In MaxReq Wait: %d",
		   i+1, server->conn_id,
		   server->credits,
		   server->echo_credits,
		   server->oplock_credits,
		   server->dialect,
		   server->tcpStatus,
		   server->reconnect_instance,
		   server->srv_count,
		   server->sec_mode,
		   in_flight(server),
		   atomic_read(&server->in_send),
		   atomic_read(&server->num_waiters));
#ifdef CONFIG_NET_NS
	if (server->net)
		seq_printf(m, " Net namespace: %u ", server->net->ns.inum);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* NET_NS */
}

static inline const char *smb_speed_to_str(size_t bps)
{
	size_t mbps = bps / 1000 / 1000;

	switch (mbps) {
	case SPEED_10:
		return "10Mbps";
	case SPEED_100:
		return "100Mbps";
	case SPEED_1000:
		return "1Gbps";
	case SPEED_2500:
		return "2.5Gbps";
	case SPEED_5000:
		return "5Gbps";
	case SPEED_10000:
		return "10Gbps";
	case SPEED_14000:
		return "14Gbps";
	case SPEED_20000:
		return "20Gbps";
	case SPEED_25000:
		return "25Gbps";
	case SPEED_40000:
		return "40Gbps";
	case SPEED_50000:
		return "50Gbps";
	case SPEED_56000:
		return "56Gbps";
	case SPEED_100000:
		return "100Gbps";
	case SPEED_200000:
		return "200Gbps";
	case SPEED_400000:
		return "400Gbps";
	case SPEED_800000:
		return "800Gbps";
	default:
		return "Unknown";
	}
}

static void
cifs_dump_iface(struct seq_file *m, struct cifs_server_iface *iface)
{
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)&iface->sockaddr;
	struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&iface->sockaddr;

	seq_printf(m, "\tSpeed: %s\n", smb_speed_to_str(iface->speed));
	seq_puts(m, "\t\tCapabilities: ");
	if (iface->rdma_capable)
		seq_puts(m, "rdma ");
	if (iface->rss_capable)
		seq_puts(m, "rss ");
	if (!iface->rdma_capable && !iface->rss_capable)
		seq_puts(m, "None");
	seq_putc(m, '\n');
	if (iface->sockaddr.ss_family == AF_INET)
		seq_printf(m, "\t\tIPv4: %pI4\n", &ipv4->sin_addr);
	else if (iface->sockaddr.ss_family == AF_INET6)
		seq_printf(m, "\t\tIPv6: %pI6\n", &ipv6->sin6_addr);
	if (!iface->is_active)
		seq_puts(m, "\t\t[for-cleanup]\n");
}

int klpp_cifs_debug_data_proc_show(struct seq_file *m, void *v)
{
	struct mid_q_entry *mid_entry;
	struct TCP_Server_Info *server;
	struct TCP_Server_Info *chan_server;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;
	struct cifs_server_iface *iface;
	int c, i, j;

	seq_puts(m,
		    "Display Internal CIFS Data Structures for Debugging\n"
		    "---------------------------------------------------\n");
	seq_printf(m, "CIFS Version %s\n", CIFS_VERSION);
	seq_printf(m, "Features:");
#ifdef CONFIG_CIFS_DFS_UPCALL
	seq_printf(m, " DFS");
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_CIFS_FSCACHE
	seq_printf(m, ",FSCACHE");
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_CIFS_SMB_DIRECT
#error "klp-ccp: non-taken branch"
#endif
#ifdef CONFIG_CIFS_STATS2
	seq_printf(m, ",STATS2");
#else
	seq_printf(m, ",STATS");
#endif
#ifdef CONFIG_CIFS_DEBUG2
#error "klp-ccp: non-taken branch"
#elif defined(CONFIG_CIFS_DEBUG)
	seq_printf(m, ",DEBUG");
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_CIFS_ALLOW_INSECURE_LEGACY
	seq_printf(m, ",ALLOW_INSECURE_LEGACY");
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_CIFS_POSIX
	seq_printf(m, ",CIFS_POSIX");
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_CIFS_UPCALL
	seq_printf(m, ",UPCALL(SPNEGO)");
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_CIFS_XATTR
	seq_printf(m, ",XATTR");
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	seq_printf(m, ",ACL");
#ifdef CONFIG_CIFS_SWN_UPCALL
	seq_puts(m, ",WITNESS");
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	seq_putc(m, '\n');
	seq_printf(m, "CIFSMaxBufSize: %d\n", CIFSMaxBufSize);
	seq_printf(m, "Active VFS Requests: %d\n", GlobalTotalActiveXid);

	seq_printf(m, "\nServers: ");

	c = 0;
	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(server, &cifs_tcp_ses_list, tcp_ses_list) {
		/* channel info will be printed as a part of sessions below */
		if (CIFS_SERVER_IS_CHAN(server))
			continue;

		c++;
		seq_printf(m, "\n%d) ConnectionId: 0x%llx ",
			c, server->conn_id);

		spin_lock(&server->srv_lock);
		if (server->hostname)
			seq_printf(m, "Hostname: %s ", server->hostname);
		seq_printf(m, "\nClientGUID: %pUL", server->client_guid);
		spin_unlock(&server->srv_lock);
#ifdef CONFIG_CIFS_SMB_DIRECT
#error "klp-ccp: non-taken branch"
#endif
		seq_printf(m, "\nNumber of credits: %d,%d,%d Dialect 0x%x",
			server->credits,
			server->echo_credits,
			server->oplock_credits,
			server->dialect);
		if (server->compress_algorithm == SMB3_COMPRESS_LZNT1)
			seq_printf(m, " COMPRESS_LZNT1");
		else if (server->compress_algorithm == SMB3_COMPRESS_LZ77)
			seq_printf(m, " COMPRESS_LZ77");
		else if (server->compress_algorithm == SMB3_COMPRESS_LZ77_HUFF)
			seq_printf(m, " COMPRESS_LZ77_HUFF");
		if (server->sign)
			seq_printf(m, " signed");
		if (server->posix_ext_supported)
			seq_printf(m, " posix");
		if (server->nosharesock)
			seq_printf(m, " nosharesock");

		if (server->rdma)
			seq_printf(m, "\nRDMA ");
		seq_printf(m, "\nTCP status: %d Instance: %d"
				"\nLocal Users To Server: %d SecMode: 0x%x Req On Wire: %d",
				server->tcpStatus,
				server->reconnect_instance,
				server->srv_count,
				server->sec_mode, in_flight(server));
#ifdef CONFIG_NET_NS
		if (server->net)
			seq_printf(m, " Net namespace: %u ", server->net->ns.inum);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* NET_NS */
		seq_printf(m, "\nIn Send: %d In MaxReq Wait: %d",
				atomic_read(&server->in_send),
				atomic_read(&server->num_waiters));

		if (server->leaf_fullpath) {
			seq_printf(m, "\nDFS leaf full path: %s",
				   server->leaf_fullpath);
		}

		seq_printf(m, "\n\n\tSessions: ");
		i = 0;
		list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
			spin_lock(&ses->ses_lock);
			if (ses->ses_status == SES_EXITING) {
				spin_unlock(&ses->ses_lock);
				continue;
			}
			i++;
			if ((ses->serverDomain == NULL) ||
				(ses->serverOS == NULL) ||
				(ses->serverNOS == NULL)) {
				seq_printf(m, "\n\t%d) Address: %s Uses: %d Capability: 0x%x\tSession Status: %d ",
					i, ses->ip_addr, ses->ses_count,
					ses->capabilities, ses->ses_status);
				if (ses->session_flags & SMB2_SESSION_FLAG_IS_GUEST)
					seq_printf(m, "Guest ");
				else if (ses->session_flags & SMB2_SESSION_FLAG_IS_NULL)
					seq_printf(m, "Anonymous ");
			} else {
				seq_printf(m,
				    "\n\t%d) Name: %s  Domain: %s Uses: %d OS: %s "
				    "\n\tNOS: %s\tCapability: 0x%x"
					"\n\tSMB session status: %d ",
				i, ses->ip_addr, ses->serverDomain,
				ses->ses_count, ses->serverOS, ses->serverNOS,
				ses->capabilities, ses->ses_status);
			}
			spin_unlock(&ses->ses_lock);

			seq_printf(m, "\n\tSecurity type: %s ",
				get_security_type_str(server->ops->select_sectype(server, ses->sectype)));

			/* dump session id helpful for use with network trace */
			seq_printf(m, " SessionId: 0x%llx", ses->Suid);
			if (ses->session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA) {
				seq_puts(m, " encrypted");
				/* can help in debugging to show encryption type */
				if (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM)
					seq_puts(m, "(gcm256)");
			}
			if (ses->sign)
				seq_puts(m, " signed");

			seq_printf(m, "\n\tUser: %d Cred User: %d",
				   from_kuid(&init_user_ns, ses->linux_uid),
				   from_kuid(&init_user_ns, ses->cred_uid));

			if (ses->dfs_root_ses) {
				seq_printf(m, "\n\tDFS root session id: 0x%llx",
					   ses->dfs_root_ses->Suid);
			}

			spin_lock(&ses->chan_lock);
			if (CIFS_CHAN_NEEDS_RECONNECT(ses, 0))
				seq_puts(m, "\tPrimary channel: DISCONNECTED ");
			if (CIFS_CHAN_IN_RECONNECT(ses, 0))
				seq_puts(m, "\t[RECONNECTING] ");

			if (ses->chan_count > 1) {
				seq_printf(m, "\n\n\tExtra Channels: %zu ",
					   ses->chan_count-1);
				for (j = 1; j < ses->chan_count; j++) {
					cifs_dump_channel(m, j, &ses->chans[j]);
					if (CIFS_CHAN_NEEDS_RECONNECT(ses, j))
						seq_puts(m, "\tDISCONNECTED ");
					if (CIFS_CHAN_IN_RECONNECT(ses, j))
						seq_puts(m, "\t[RECONNECTING] ");
				}
			}
			spin_unlock(&ses->chan_lock);

			seq_puts(m, "\n\n\tShares: ");
			j = 0;

			seq_printf(m, "\n\t%d) IPC: ", j);
			if (ses->tcon_ipc)
				cifs_debug_tcon(m, ses->tcon_ipc);
			else
				seq_puts(m, "none\n");

			list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
				++j;
				seq_printf(m, "\n\t%d) ", j);
				cifs_debug_tcon(m, tcon);
			}

			spin_lock(&ses->iface_lock);
			if (ses->iface_count)
				seq_printf(m, "\n\n\tServer interfaces: %zu"
					   "\tLast updated: %lu seconds ago",
					   ses->iface_count,
					   (jiffies - ses->iface_last_update) / HZ);
			j = 0;
			list_for_each_entry(iface, &ses->iface_list,
						 iface_head) {
				seq_printf(m, "\n\t%d)", ++j);
				cifs_dump_iface(m, iface);
				if (is_ses_using_iface(ses, iface))
					seq_puts(m, "\t\t[CONNECTED]\n");
			}
			spin_unlock(&ses->iface_lock);

			seq_puts(m, "\n\n\tMIDs: ");
			spin_lock(&ses->chan_lock);
			for (j = 0; j < ses->chan_count; j++) {
				chan_server = ses->chans[j].server;
				if (!chan_server)
					continue;

				if (list_empty(&chan_server->pending_mid_q))
					continue;

				seq_printf(m, "\n\tServer ConnectionId: 0x%llx",
					   chan_server->conn_id);
				spin_lock(&chan_server->mid_lock);
				list_for_each_entry(mid_entry, &chan_server->pending_mid_q, qhead) {
					seq_printf(m, "\n\t\tState: %d com: %d pid: %d cbdata: %p mid %llu",
						   mid_entry->mid_state,
						   le16_to_cpu(mid_entry->command),
						   mid_entry->pid,
						   mid_entry->callback_data,
						   mid_entry->mid);
				}
				spin_unlock(&chan_server->mid_lock);
			}
			spin_unlock(&ses->chan_lock);
			seq_puts(m, "\n--\n");
		}
		if (i == 0)
			seq_printf(m, "\n\t\t[NONE]");
	}
	if (c == 0)
		seq_printf(m, "\n\t[NONE]");

	spin_unlock(&cifs_tcp_ses_lock);
	seq_putc(m, '\n');
	cifs_swn_dump(m);

	/* BB add code to dump additional info such as TCP session info now */
	return 0;
}

#else
#error "klp-ccp: non-taken branch"
#endif /* PROC_FS */


#include "livepatch_bsc1225819.h"
#include <linux/livepatch.h>

extern typeof(CIFSMaxBufSize) CIFSMaxBufSize
	 KLP_RELOC_SYMBOL(cifs, cifs, CIFSMaxBufSize);
extern typeof(GlobalTotalActiveXid) GlobalTotalActiveXid
	 KLP_RELOC_SYMBOL(cifs, cifs, GlobalTotalActiveXid);
extern typeof(cifs_debug_tcon) cifs_debug_tcon
	 KLP_RELOC_SYMBOL(cifs, cifs, cifs_debug_tcon);
extern typeof(cifs_swn_dump) cifs_swn_dump
	 KLP_RELOC_SYMBOL(cifs, cifs, cifs_swn_dump);
extern typeof(cifs_tcp_ses_list) cifs_tcp_ses_list
	 KLP_RELOC_SYMBOL(cifs, cifs, cifs_tcp_ses_list);
extern typeof(cifs_tcp_ses_lock) cifs_tcp_ses_lock
	 KLP_RELOC_SYMBOL(cifs, cifs, cifs_tcp_ses_lock);
extern typeof(is_ses_using_iface) is_ses_using_iface
	 KLP_RELOC_SYMBOL(cifs, cifs, is_ses_using_iface);
