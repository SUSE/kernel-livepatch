/*
 * livepatch_bsc1225012
 *
 * Fix for CVE-2024-35867, bsc#1225012
 *
 *  Upstream commit:
 *  0865ffefea19 ("smb: client: fix potential UAF in cifs_stats_proc_show()")
 *
 *  SLE12-SP5 commit:
 *  adb391f231678e4bf518f450f3c0a74fb4fd204a
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  45bad5abc4ef32c4a9d02be3833c11a523d7eaa9
 *
 *  SLE15-SP6 commit:
 *  3a82d6a1e7f0ad1bf63ebbd35264ef67ab39dc0a
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


/* klp-ccp: from fs/cifs/cifs_debug.c */
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/uaccess.h>
/* klp-ccp: from fs/cifs/cifspdu.h */
#include <net/sock.h>
#include <asm/unaligned.h>

#define CIFS_CRYPTO_KEY_SIZE (8)

#define SMB3_SIGN_KEY_SIZE (16)

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

typedef struct { /* data block encoding of response to level 263 QPathInfo */
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le32 Attributes;
	__u32 Pad1;
	__le64 AllocationSize;
	__le64 EndOfFile;	/* size ie offset to first free byte in file */
	__le32 NumberOfLinks;	/* hard links */
	__u8 DeletePending;
	__u8 Directory;
	__u16 Pad2;
	__le64 IndexNumber;
	__le32 EASize;
	__le32 AccessFlags;
	__u64 IndexNumber1;
	__le64 CurrentByteOffset;
	__le32 Mode;
	__le32 AlignmentRequirement;
	__le32 FileNameLength;
	char FileName[1];
} __attribute__((packed)) FILE_ALL_INFO;

typedef struct {
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le32 Attributes;
	__u32 Pad;
} __attribute__((packed)) FILE_BASIC_INFO;

/* klp-ccp: from fs/cifs/cifsglob.h */
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
/* klp-ccp: from fs/cifs/cifs_fs_sb.h */
#include <linux/rbtree.h>

#ifndef _CIFS_FS_SB_H

struct cifs_sb_info {
	struct rb_root tlink_tree;
	spinlock_t tlink_tree_lock;
	struct tcon_link *master_tlink;
	struct nls_table *local_nls;
	unsigned int bsize;
	unsigned int rsize;
	unsigned int wsize;
	/* attribute cache timemout for files and directories in jiffies */
	unsigned long acregmax;
	unsigned long acdirmax;
	atomic_t active;
	kuid_t	mnt_uid;
	kgid_t	mnt_gid;
	kuid_t	mnt_backupuid;
	kgid_t	mnt_backupgid;
	umode_t	mnt_file_mode;
	umode_t	mnt_dir_mode;
	unsigned int mnt_cifs_flags;
	char   *mountdata; /* options received at mount time or via DFS refs */
	struct delayed_work prune_tlinks;
	struct rcu_head rcu;

	/* only used when CIFS_MOUNT_USE_PREFIX_PATH is set */
	char *prepath;

	/* randomly generated 128-bit number for indexing dfs mount groups in referral cache */
	uuid_t dfs_mount_id;
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

/* klp-ccp: from fs/cifs/cifsglob.h */
#include <uapi/linux/cifs/cifs_mount.h>
/* klp-ccp: from fs/cifs/smb2pdu.h */
#include <net/sock.h>

#define NUMBER_OF_SMB2_COMMANDS	0x0013

#define SMB2_CLIENT_GUID_SIZE 16

#define SMB2_PREAUTH_HASH_SIZE 64

struct smb2_file_all_info { /* data block encoding of response to level 18 */
	__le64 CreationTime;	/* Beginning of FILE_BASIC_INFO equivalent */
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le32 Attributes;
	__u32  Pad1;		/* End of FILE_BASIC_INFO_INFO equivalent */
	__le64 AllocationSize;	/* Beginning of FILE_STANDARD_INFO equivalent */
	__le64 EndOfFile;	/* size ie offset to first free byte in file */
	__le32 NumberOfLinks;	/* hard links */
	__u8   DeletePending;
	__u8   Directory;
	__u16  Pad2;		/* End of FILE_STANDARD_INFO equivalent */
	__le64 IndexNumber;
	__le32 EASize;
	__le32 AccessFlags;
	__le64 CurrentByteOffset;
	__le32 Mode;
	__le32 AlignmentRequirement;
	__le32 FileNameLength;
	char   FileName[1];
} __packed;

/* klp-ccp: from fs/cifs/cifsglob.h */
#define MAX_TREE_SIZE (2 + CIFS_NI_MAXHOST + 1 + CIFS_MAX_SHARE_LEN + 1)

#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

#define SERVER_NAME_LENGTH 80
#define SERVER_NAME_LEN_WITH_NULL     (SERVER_NAME_LENGTH + 1)

enum statusEnum {
	CifsNew = 0,
	CifsGood,
	CifsExiting,
	CifsNeedReconnect,
	CifsNeedNegotiate
};

enum securityEnum {
	Unspecified = 0,	/* not specified */
	LANMAN,			/* Legacy LANMAN auth */
	NTLM,			/* Legacy NTLM012 auth with NTLM hash */
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

struct smb_rqst;

struct mid_q_entry;
struct TCP_Server_Info;
struct cifsFileInfo;
struct cifs_ses;
struct cifs_tcon;
struct dfs_info3_param;

struct smb_vol;
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
	int (*negotiate)(const unsigned int, struct cifs_ses *);
	/* set negotiated write size */
	unsigned int (*negotiate_wsize)(struct cifs_tcon *, struct smb_vol *);
	/* set negotiated read size */
	unsigned int (*negotiate_rsize)(struct cifs_tcon *, struct smb_vol *);
	/* setup smb sessionn */
	int (*sess_setup)(const unsigned int, struct cifs_ses *,
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
	int (*query_path_info)(const unsigned int, struct cifs_tcon *,
			       struct cifs_sb_info *, const char *,
			       FILE_ALL_INFO *, bool *, bool *);
	/* query file data from the server */
	int (*query_file_info)(const unsigned int, struct cifs_tcon *,
			       struct cifs_fid *, FILE_ALL_INFO *);
	/* get server index number */
	int (*get_srv_inum)(const unsigned int, struct cifs_tcon *,
			    struct cifs_sb_info *, const char *,
			    u64 *uniqueid, FILE_ALL_INFO *);
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
	int (*open)(const unsigned int, struct cifs_open_parms *,
		    __u32 *, FILE_ALL_INFO *);
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
	int (*oplock_response)(struct cifs_tcon *, struct cifs_fid *,
			       struct cifsInodeInfo *);
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
	int (*generate_signingkey)(struct cifs_ses *);
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
	void (*is_network_name_deleted)(char *buf, struct TCP_Server_Info *srv);
};

struct TCP_Server_Info {
	struct list_head tcp_ses_list;
	struct list_head smb_ses_list;
	spinlock_t srv_lock;  /* protect anything here that is not protected */
	int srv_count; /* reference counter */
	/* 15 character server name + 0x20 16th byte indicating type = srv */
	char server_RFC1001_name[RFC1001_NAME_LEN_WITH_NULL];
	struct smb_version_operations	*ops;
	struct smb_version_values	*vals;
	/* updates to tcpStatus protected by GlobalMid_Lock */
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
	struct mutex srv_mutex;
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
#ifdef CONFIG_CIFS_FSCACHE
	struct fscache_cookie   *fscache; /* client index cache cookie */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
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
	__le16	cipher_type;
	 /* save initital negprot hash */
	__u8	preauth_sha_hash[SMB2_PREAUTH_HASH_SIZE];
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
#ifdef CONFIG_CIFS_DFS_UPCALL
	bool is_dfs_conn; /* if a dfs connection */
	struct mutex refpath_lock; /* protects leaf_fullpath */
	/*
	 * Canonical DFS full paths that were used to chase referrals in mount and reconnect.
	 *
	 * origin_fullpath: first or original referral path
	 * leaf_fullpath: last referral path (might be changed due to nested links in reconnect)
	 *
	 * current_fullpath: pointer to either origin_fullpath or leaf_fullpath
	 * NOTE: cannot be accessed outside cifs_reconnect() and smb2_reconnect()
	 *
	 * format: \\HOST\SHARE\[OPTIONAL PATH]
	 */
	char *origin_fullpath, *leaf_fullpath, *current_fullpath;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct cifs_ses {
	struct list_head smb_ses_list;
	struct list_head tcon_list;
	struct cifs_tcon *tcon_ipc;
	spinlock_t ses_lock;  /* protect anything here that is not protected */
	struct mutex session_mutex;
	struct TCP_Server_Info *server;	/* pointer to server info */
	int ses_count;		/* reference counter */
	enum statusEnum status;  /* updates protected by cifs_tcp_ses_lock */
	unsigned int overrideSecFlg;  /* if non-zero override global sec flags */
	char *serverOS;		/* name of operating system underlying server */
	char *serverNOS;	/* name of network operating system of server */
	char *serverDomain;	/* security realm of server */
	__u64 Suid;		/* remote smb uid  */
	kuid_t linux_uid;	/* overriding owner of files on the mount */
	kuid_t cred_uid;	/* owner of credentials */
	unsigned int capabilities;
	char serverName[SERVER_NAME_LEN_WITH_NULL];
	char *user_name;	/* must not be null except during init of sess
				   and after mount option parsing we fill it */
	char *domainName;
	char *password;
	struct session_key auth_key;
	struct ntlmssp_auth *ntlmssp; /* ciphertext, flags, server challenge */
	enum securityEnum sectype; /* what security flavor was specified? */
	bool sign;		/* is signing required? */
	bool need_reconnect:1; /* connection reset, uid now invalid */
	bool domainAuto:1;
	__u16 session_flags;
	__u8 smb3signingkey[SMB3_SIGN_KEY_SIZE];
	__u8 smb3encryptionkey[SMB3_SIGN_KEY_SIZE];
	__u8 smb3decryptionkey[SMB3_SIGN_KEY_SIZE];
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
	struct cifs_server_iface *iface_list;
	size_t iface_count;
	unsigned long iface_last_update; /* jiffies */
};

struct cached_fid {
	bool is_valid:1;	/* Do we have a useable root fid */
	bool file_all_info_is_valid:1;
	bool has_lease:1;
	unsigned long time; /* jiffies of when lease was taken */
	struct kref refcount;
	struct cifs_fid *fid;
	struct mutex fid_mutex;
	struct cifs_tcon *tcon;
	struct dentry *dentry;
	struct work_struct lease_break;
	struct smb2_file_all_info file_all_info;
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
	char treeName[MAX_TREE_SIZE + 1]; /* UNC name of resource in ASCII */
	char *nativeFileSystem;
	char *password;		/* for share-level security */
	__u32 tid;		/* The 4 byte tree id */
	__u16 Flags;		/* optional support bits */
	enum statusEnum tidStatus;
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
	struct fscache_cookie *fscache;	/* cookie for share */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct list_head pending_opens;	/* list of incomplete opens */
	struct cached_fid crfid; /* Cached root fid */

#ifdef CONFIG_CIFS_DFS_UPCALL
	struct list_head ulist; /* cache update list */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

static struct list_head		(*klpe_cifs_tcp_ses_list);

static spinlock_t		(*klpe_cifs_tcp_ses_lock);

static unsigned int (*klpe_GlobalCurrentXid);

static unsigned int (*klpe_GlobalMaxActiveXid);

static atomic_t (*klpe_sesInfoAllocCount);
static atomic_t (*klpe_tconInfoAllocCount);
static atomic_t (*klpe_tcpSesAllocCount);
static atomic_t (*klpe_tcpSesReconnectCount);
static atomic_t (*klpe_tconInfoReconnectCount);

static atomic_t (*klpe_buf_alloc_count);
static atomic_t (*klpe_small_buf_alloc_count);
#ifdef CONFIG_CIFS_STATS2
static atomic_t (*klpe_total_buf_alloc_count);
static atomic_t (*klpe_total_small_buf_alloc_count);
#endif

static unsigned int (*klpe_cifs_min_rcv);
static unsigned int (*klpe_cifs_min_small);

static atomic_t (*klpe_mid_count);

/* klp-ccp: from include/linux/nls.h */
#define _LINUX_NLS_H

/* klp-ccp: from fs/cifs/trace.h */
#include <trace/define_trace.h>
/* klp-ccp: from fs/cifs/cifsproto.h */
#ifdef CONFIG_CIFS_DFS_UPCALL

/* klp-ccp: from fs/cifs/dfs_cache.h */
#include <linux/nls.h>
#include <linux/list.h>
#include <linux/uuid.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from fs/cifs/cifsproto.h */
#endif

/* klp-ccp: from fs/cifs/cifsfs.h */
#include <linux/hash.h>

/* klp-ccp: from fs/cifs/cifs_debug.c */
#ifdef CONFIG_PROC_FS

static inline bool klpp_cifs_ses_exiting(struct cifs_ses *ses)
{
	bool ret;

	spin_lock(&ses->ses_lock);
	ret = ses->status == CifsExiting;
	spin_unlock(&ses->ses_lock);
	return ret;
}

int klpp_cifs_stats_proc_show(struct seq_file *m, void *v)
{
	int i;
#ifdef CONFIG_CIFS_STATS2
	int j;
#endif /* STATS2 */
	struct list_head *tmp2, *tmp3;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;

	seq_printf(m, "Resources in use\nCIFS Session: %d\n",
			(*klpe_sesInfoAllocCount).counter);
	seq_printf(m, "Share (unique mount targets): %d\n",
			(*klpe_tconInfoAllocCount).counter);
	seq_printf(m, "SMB Request/Response Buffer: %d Pool size: %d\n",
			(*klpe_buf_alloc_count).counter,
			(*klpe_cifs_min_rcv) + (*klpe_tcpSesAllocCount).counter);
	seq_printf(m, "SMB Small Req/Resp Buffer: %d Pool size: %d\n",
			(*klpe_small_buf_alloc_count).counter, (*klpe_cifs_min_small));
#ifdef CONFIG_CIFS_STATS2
	seq_printf(m, "Total Large %d Small %d Allocations\n",
				atomic_read(&(*klpe_total_buf_alloc_count)),
				atomic_read(&(*klpe_total_small_buf_alloc_count)));
#endif /* CONFIG_CIFS_STATS2 */
	seq_printf(m, "Operations (MIDs): %d\n", atomic_read(&(*klpe_mid_count)));
	seq_printf(m,
		"\n%d session %d share reconnects\n",
		(*klpe_tcpSesReconnectCount).counter, (*klpe_tconInfoReconnectCount).counter);

	seq_printf(m,
		"Total vfs operations: %d maximum at one time: %d\n",
		(*klpe_GlobalCurrentXid), (*klpe_GlobalMaxActiveXid));

	i = 0;
	spin_lock(&(*klpe_cifs_tcp_ses_lock));
	list_for_each_entry(server, &(*klpe_cifs_tcp_ses_list), tcp_ses_list) {
		seq_printf(m, "\nMax requests in flight: %d", server->max_in_flight);
#ifdef CONFIG_CIFS_STATS2
		seq_puts(m, "\nTotal time spent processing by command. Time ");
		seq_printf(m, "units are jiffies (%d per second)\n", HZ);
		seq_puts(m, "  SMB3 CMD\tNumber\tTotal Time\tFastest\tSlowest\n");
		seq_puts(m, "  --------\t------\t----------\t-------\t-------\n");
		for (j = 0; j < NUMBER_OF_SMB2_COMMANDS; j++)
			seq_printf(m, "  %d\t\t%d\t%llu\t\t%u\t%u\n", j,
				atomic_read(&server->num_cmds[j]),
				server->time_per_cmd[j],
				server->fastest_cmd[j],
				server->slowest_cmd[j]);
		for (j = 0; j < NUMBER_OF_SMB2_COMMANDS; j++)
			if (atomic_read(&server->smb2slowcmd[j]))
				seq_printf(m, "  %d slow responses from %s for command %d\n",
					atomic_read(&server->smb2slowcmd[j]),
					server->hostname, j);
#endif /* STATS2 */
		list_for_each(tmp2, &server->smb_ses_list) {
			ses = list_entry(tmp2, struct cifs_ses,
					 smb_ses_list);
			if (klpp_cifs_ses_exiting(ses))
				continue;
			list_for_each(tmp3, &ses->tcon_list) {
				tcon = list_entry(tmp3,
						  struct cifs_tcon,
						  tcon_list);
				i++;
				seq_printf(m, "\n%d) %s", i, tcon->treeName);
				if (tcon->need_reconnect)
					seq_puts(m, "\tDISCONNECTED ");
				seq_printf(m, "\nSMBs: %d",
					   atomic_read(&tcon->num_smbs_sent));
				if (server->ops->print_stats)
					server->ops->print_stats(m, tcon);
			}
		}
	}
	spin_unlock(&(*klpe_cifs_tcp_ses_lock));

	seq_putc(m, '\n');
	return 0;
}

#else
#error "klp-ccp: non-taken branch"
#endif /* PROC_FS */


#include "livepatch_bsc1225012.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "cifs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "GlobalCurrentXid", (void *)&klpe_GlobalCurrentXid, "cifs" },
	{ "GlobalMaxActiveXid", (void *)&klpe_GlobalMaxActiveXid, "cifs" },
	{ "buf_alloc_count", (void *)&klpe_buf_alloc_count, "cifs" },
	{ "cifs_min_rcv", (void *)&klpe_cifs_min_rcv, "cifs" },
	{ "cifs_min_small", (void *)&klpe_cifs_min_small, "cifs" },
	{ "cifs_tcp_ses_list", (void *)&klpe_cifs_tcp_ses_list, "cifs" },
	{ "cifs_tcp_ses_lock", (void *)&klpe_cifs_tcp_ses_lock, "cifs" },
	{ "mid_count", (void *)&klpe_mid_count, "cifs" },
	{ "sesInfoAllocCount", (void *)&klpe_sesInfoAllocCount, "cifs" },
	{ "small_buf_alloc_count", (void *)&klpe_small_buf_alloc_count,
	  "cifs" },
	{ "tconInfoAllocCount", (void *)&klpe_tconInfoAllocCount, "cifs" },
	{ "tconInfoReconnectCount", (void *)&klpe_tconInfoReconnectCount,
	  "cifs" },
	{ "tcpSesAllocCount", (void *)&klpe_tcpSesAllocCount, "cifs" },
	{ "tcpSesReconnectCount", (void *)&klpe_tcpSesReconnectCount, "cifs" },
#ifdef CONFIG_CIFS_STATS2
	{ "total_buf_alloc_count", (void *)&klpe_total_buf_alloc_count,
	  "cifs" },
	{ "total_small_buf_alloc_count",
	  (void *)&klpe_total_small_buf_alloc_count, "cifs" },
#endif /* CONFIG_CIFS_STATS2 */
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

int livepatch_bsc1225012_init(void)
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

void livepatch_bsc1225012_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
