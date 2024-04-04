/*
 * livepatch_bsc1219078
 *
 * Fix for CVE-2024-0565, bsc#1219078
 *
 *  Upstream commit:
 *  eec04ea11969 ("smb: client: fix OOB in receive_encrypted_standard()")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  59d97af2b0a039ce29b4bc5434d9a2752ba06f63
 *
 *  SLE15-SP4 and -SP5 commit:
 *  3cac9c2e0d55b481dc8b039d713bdafd911a6623
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from fs/cifs/smb2ops.c */
#include <linux/scatterlist.h>
#include <linux/uuid.h>
#include <crypto/aead.h>
#include <uapi/linux/magic.h>
/* klp-ccp: from fs/cifs/cifsfs.h */
#include <linux/hash.h>
/* klp-ccp: from fs/cifs/cifsglob.h */
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/workqueue.h>
/* klp-ccp: from fs/cifs/cifs_fs_sb.h */
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

/* klp-ccp: from fs/cifs/cifsglob.h */
#include <uapi/linux/cifs/cifs_mount.h>

/* klp-ccp: from fs/smbfs_common/smb2pdu.h */
#define NUMBER_OF_SMB2_COMMANDS	0x0013

struct smb2_hdr {
	__le32 ProtocolId;	/* 0xFE 'S' 'M' 'B' */
	__le16 StructureSize;	/* 64 */
	__le16 CreditCharge;	/* MBZ */
	__le32 Status;		/* Error from server */
	__le16 Command;
	__le16 CreditRequest;	/* CreditResponse */
	__le32 Flags;
	__le32 NextCommand;
	__le64 MessageId;
	union {
		struct {
			__le32 ProcessId;
			__le32  TreeId;
		} __packed SyncId;
		__le64  AsyncId;
	} __packed Id;
	__le64  SessionId;
	__u8   Signature[16];
} __packed;

struct smb2_transform_hdr {
	__le32 ProtocolId;	/* 0xFD 'S' 'M' 'B' */
	__u8   Signature[16];
	__u8   Nonce[16];
	__le32 OriginalMessageSize;
	__u16  Reserved1;
	__le16 Flags; /* EncryptionAlgorithm for 3.0, enc enabled for 3.1.1 */
	__le64  SessionId;
} __packed;

#define SMB2_CLIENT_GUID_SIZE		16

#define SMB2_PREAUTH_HASH_SIZE 64

/* klp-ccp: from fs/cifs/cifsglob.h */
#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

#define MAX_COMPOUND 5

/* klp-ccp: from fs/cifs/cifspdu.h */
#include <net/sock.h>

#define MAX_CIFS_SMALL_BUFFER_SIZE 448 /* big enough for most */

#define CIFS_CRYPTO_KEY_SIZE (8)

typedef struct {
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le32 Attributes;
	__u32 Pad;
} __attribute__((packed)) FILE_BASIC_INFO;

/* klp-ccp: from fs/cifs/cifsglob.h */
enum statusEnum {
	CifsNew = 0,
	CifsGood,
	CifsExiting,
	CifsNeedReconnect,
	CifsNeedNegotiate,
	CifsInNegotiate,
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
	void (*is_network_name_deleted)(char *buf, struct TCP_Server_Info *srv);
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

#define HEADER_SIZE(server) (server->vals->header_size)
#define MAX_HEADER_SIZE(server) (server->vals->max_header_size)

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

	/*
	 * If this is a session channel,
	 * primary_server holds the ref-counted
	 * pointer to primary channel connection for the session.
	 */
	struct TCP_Server_Info *primary_server;

#ifdef CONFIG_CIFS_SWN_UPCALL
	bool use_swn_dstaddr;
	struct sockaddr_storage swn_dstaddr;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct mutex refpath_lock; /* protects leaf_fullpath */
	/*
	 * origin_fullpath: Canonical copy of smb3_fs_context::source.
	 *                  It is used for matching existing DFS tcons.
	 *
	 * leaf_fullpath: Canonical DFS referral path related to this
	 *                connection.
	 *                It is used in DFS cache refresher, reconnect and may
	 *                change due to nested DFS links.
	 *
	 * Both protected by @refpath_lock and @srv_lock.  The @refpath_lock is
	 * mosly used for not requiring a copy of @leaf_fullpath when getting
	 * cached or new DFS referrals (which might also sleep during I/O).
	 * While @srv_lock is held for making string and NULL comparions against
	 * both fields as in mount(2) and cache refresh.
	 *
	 * format: \\HOST\SHARE[\OPTIONAL PATH]
	 */
	char *origin_fullpath, *leaf_fullpath;
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

#define   CIFS_SMALL_BUFFER     1
#define   CIFS_LARGE_BUFFER     2

static unsigned int (*klpe_CIFSMaxBufSize);

static struct workqueue_struct *(*klpe_decrypt_wq);

/* klp-ccp: from fs/cifs/cifsproto.h */
#include <linux/nls.h>

/* klp-ccp: from fs/cifs/trace.h */
#if !defined(_CIFS_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/net.h>
#include <linux/inet.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _CIFS_TRACE_H */

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

static struct smb_hdr *(*klpe_cifs_buf_get)(void);

static struct smb_hdr *(*klpe_cifs_small_buf_get)(void);

static void (*klpe_free_rsp_buf)(int, void *);

static int (*klpe_cifs_handle_standard)(struct TCP_Server_Info *server,
				struct mid_q_entry *mid);

static int (*klpe_cifs_discard_remaining_data)(struct TCP_Server_Info *server);

static int (*klpe_cifs_reconnect)(struct TCP_Server_Info *server,
			  bool mark_smb_session);

static int (*klpe_cifs_read_from_socket)(struct TCP_Server_Info *server, char *buf,
			         unsigned int to_read);

static int (*klpe_cifs_read_page_from_socket)(struct TCP_Server_Info *server,
					struct page *page,
					unsigned int page_offset,
					unsigned int to_read);

/* klp-ccp: from fs/cifs/cifs_debug.h */
static int (*klpe_cifsFYI);

#define CIFS_INFO	0x01
#define VFS 1
#define FYI 2

#define NOISY 0
#define ONCE 8
#define klpr_cifs_dbg_func(ratefunc, type, fmt, ...)			\
do {									\
	if ((type) & FYI && (*klpe_cifsFYI) & CIFS_INFO) {		\
		pr_debug_ ## ratefunc("%s: " fmt,			\
				      __FILE__, ##__VA_ARGS__);		\
	} else if ((type) & VFS) {					\
		pr_err_ ## ratefunc("VFS: " fmt, ##__VA_ARGS__);	\
	} else if ((type) & NOISY && (NOISY != 0)) {			\
		pr_debug_ ## ratefunc(fmt, ##__VA_ARGS__);		\
	}								\
} while (0)

#define klpr_cifs_dbg(type, fmt, ...)						\
do {										\
	if ((type) & ONCE)							\
		klpr_cifs_dbg_func(once, type, fmt, ##__VA_ARGS__);		\
	else									\
		klpr_cifs_dbg_func(ratelimited, type, fmt, ##__VA_ARGS__);	\
} while (0)

#define klpr_cifs_server_dbg_func(ratefunc, type, fmt, ...)		\
do {									\
	const char *sn = "";						\
	if (server && server->hostname)					\
		sn = server->hostname;					\
	if ((type) & FYI && (*klpe_cifsFYI) & CIFS_INFO) {		\
		pr_debug_ ## ratefunc("%s: \\\\%s " fmt,		\
				      __FILE__, sn, ##__VA_ARGS__);	\
	} else if ((type) & VFS) {					\
		pr_err_ ## ratefunc("VFS: \\\\%s " fmt,			\
				    sn, ##__VA_ARGS__);			\
	} else if ((type) & NOISY && (NOISY != 0)) {			\
		pr_debug_ ## ratefunc("\\\\%s " fmt,			\
				      sn, ##__VA_ARGS__);		\
	}								\
} while (0)

#define klpr_cifs_server_dbg(type, fmt, ...)					\
do {										\
	if ((type) & ONCE)							\
		klpr_cifs_server_dbg_func(once, type, fmt, ##__VA_ARGS__);	\
	else									\
		klpr_cifs_server_dbg_func(ratelimited, type, fmt,		\
								##__VA_ARGS__);	\
} while (0)

/* klp-ccp: from fs/cifs/cifs_unicode.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/nls.h>

/* klp-ccp: from fs/cifs/smb2ops.c */
static struct mid_q_entry *
(*klpe_smb2_find_mid)(struct TCP_Server_Info *server, char *buf);

static int
(*klpe_decrypt_raw_data)(struct TCP_Server_Info *server, char *buf,
		 unsigned int buf_data_size, struct page **pages,
		 unsigned int npages, unsigned int page_data_size,
		 bool is_offloaded);

static int
klpr_read_data_into_pages(struct TCP_Server_Info *server, struct page **pages,
		     unsigned int npages, unsigned int len)
{
	int i;
	int length;

	for (i = 0; i < npages; i++) {
		struct page *page = pages[i];
		size_t n;

		n = len;
		if (len >= PAGE_SIZE) {
			/* enough data to fill the page */
			n = PAGE_SIZE;
			len -= n;
		} else {
			zero_user(page, len, PAGE_SIZE - len);
			len = 0;
		}
		length = (*klpe_cifs_read_page_from_socket)(server, page, 0, n);
		if (length < 0)
			return length;
		server->total_read += length;
	}

	return 0;
}

static int
(*klpe_handle_read_data)(struct TCP_Server_Info *server, struct mid_q_entry *mid,
		 char *buf, unsigned int buf_len, struct page **pages,
		 unsigned int npages, unsigned int page_data_size,
		 bool is_offloaded);

struct smb2_decrypt_work {
	struct work_struct decrypt;
	struct TCP_Server_Info *server;
	struct page **ppages;
	char *buf;
	unsigned int npages;
	unsigned int len;
};

static void (*klpe_smb2_decrypt_offload)(struct work_struct *work);

static int
klpr_receive_encrypted_read(struct TCP_Server_Info *server, struct mid_q_entry **mid,
		       int *num_mids)
{
	char *buf = server->smallbuf;
	struct smb2_transform_hdr *tr_hdr = (struct smb2_transform_hdr *)buf;
	unsigned int npages;
	struct page **pages;
	unsigned int len;
	unsigned int buflen = server->pdu_size;
	int rc;
	int i = 0;
	struct smb2_decrypt_work *dw;

	*num_mids = 1;
	len = min_t(unsigned int, buflen, server->vals->read_rsp_size +
		sizeof(struct smb2_transform_hdr)) - HEADER_SIZE(server) + 1;

	rc = (*klpe_cifs_read_from_socket)(server, buf + HEADER_SIZE(server) - 1, len);
	if (rc < 0)
		return rc;
	server->total_read += rc;

	len = le32_to_cpu(tr_hdr->OriginalMessageSize) -
		server->vals->read_rsp_size;
	npages = DIV_ROUND_UP(len, PAGE_SIZE);

	pages = kmalloc_array(npages, sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		rc = -ENOMEM;
		goto discard_data;
	}

	for (; i < npages; i++) {
		pages[i] = alloc_page(GFP_KERNEL|__GFP_HIGHMEM);
		if (!pages[i]) {
			rc = -ENOMEM;
			goto discard_data;
		}
	}

	/* read read data into pages */
	rc = klpr_read_data_into_pages(server, pages, npages, len);
	if (rc)
		goto free_pages;

	rc = (*klpe_cifs_discard_remaining_data)(server);
	if (rc)
		goto free_pages;

	/*
	 * For large reads, offload to different thread for better performance,
	 * use more cores decrypting which can be expensive
	 */

	if ((server->min_offload) && (server->in_flight > 1) &&
	    (server->pdu_size >= server->min_offload)) {
		dw = kmalloc(sizeof(struct smb2_decrypt_work), GFP_KERNEL);
		if (dw == NULL)
			goto non_offloaded_decrypt;

		dw->buf = server->smallbuf;
		server->smallbuf = (char *)(*klpe_cifs_small_buf_get)();

		INIT_WORK(&dw->decrypt, (*klpe_smb2_decrypt_offload));

		dw->npages = npages;
		dw->server = server;
		dw->ppages = pages;
		dw->len = len;
		queue_work((*klpe_decrypt_wq), &dw->decrypt);
		*num_mids = 0; /* worker thread takes care of finding mid */
		return -1;
	}

non_offloaded_decrypt:
	rc = (*klpe_decrypt_raw_data)(server, buf, server->vals->read_rsp_size,
			      pages, npages, len, false);
	if (rc)
		goto free_pages;

	*mid = (*klpe_smb2_find_mid)(server, buf);
	if (*mid == NULL)
		klpr_cifs_dbg(FYI, "mid not found\n");
	else {
		klpr_cifs_dbg(FYI, "mid found\n");
		(*mid)->decrypted = true;
		rc = (*klpe_handle_read_data)(server, *mid, buf,
				      server->vals->read_rsp_size,
				      pages, npages, len, false);
		if (rc >= 0) {
			if (server->ops->is_network_name_deleted) {
				server->ops->is_network_name_deleted(buf,
								server);
			}
		}
	}

free_pages:
	for (i = i - 1; i >= 0; i--)
		put_page(pages[i]);
	kfree(pages);
	return rc;
discard_data:
	(*klpe_cifs_discard_remaining_data)(server);
	goto free_pages;
}

static int
klpr_receive_encrypted_standard(struct TCP_Server_Info *server,
			   struct mid_q_entry **mids, char **bufs,
			   int *num_mids)
{
	int ret, length;
	char *buf = server->smallbuf;
	struct smb2_hdr *shdr;
	unsigned int pdu_length = server->pdu_size;
	unsigned int buf_size;
	unsigned int next_cmd;
	struct mid_q_entry *mid_entry;
	int next_is_large;
	char *next_buffer = NULL;

	*num_mids = 0;

	/* switch to large buffer if too big for a small one */
	if (pdu_length > MAX_CIFS_SMALL_BUFFER_SIZE) {
		server->large_buf = true;
		memcpy(server->bigbuf, buf, server->total_read);
		buf = server->bigbuf;
	}

	/* now read the rest */
	length = (*klpe_cifs_read_from_socket)(server, buf + HEADER_SIZE(server) - 1,
				pdu_length - HEADER_SIZE(server) + 1);
	if (length < 0)
		return length;
	server->total_read += length;

	buf_size = pdu_length - sizeof(struct smb2_transform_hdr);
	length = (*klpe_decrypt_raw_data)(server, buf, buf_size, NULL, 0, 0, false);
	if (length)
		return length;

	next_is_large = server->large_buf;
one_more:
	shdr = (struct smb2_hdr *)buf;
	next_cmd = le32_to_cpu(shdr->NextCommand);
	if (next_cmd) {
		if (WARN_ON_ONCE(next_cmd > pdu_length))
			return -1;
		if (next_is_large)
			next_buffer = (char *)(*klpe_cifs_buf_get)();
		else
			next_buffer = (char *)(*klpe_cifs_small_buf_get)();
		memcpy(next_buffer, buf + next_cmd, pdu_length - next_cmd);
	}

	mid_entry = (*klpe_smb2_find_mid)(server, buf);
	if (mid_entry == NULL)
		klpr_cifs_dbg(FYI, "mid not found\n");
	else {
		klpr_cifs_dbg(FYI, "mid found\n");
		mid_entry->decrypted = true;
		mid_entry->resp_buf_size = server->pdu_size;
	}

	if (*num_mids >= MAX_COMPOUND) {
		klpr_cifs_server_dbg(VFS, "too many PDUs in compound\n");
		return -1;
	}
	bufs[*num_mids] = buf;
	mids[(*num_mids)++] = mid_entry;

	if (mid_entry && mid_entry->handle)
		ret = mid_entry->handle(server, mid_entry);
	else
		ret = (*klpe_cifs_handle_standard)(server, mid_entry);

	if (ret == 0 && next_cmd) {
		pdu_length -= next_cmd;
		server->large_buf = next_is_large;
		if (next_is_large)
			server->bigbuf = buf = next_buffer;
		else
			server->smallbuf = buf = next_buffer;
		goto one_more;
	} else if (ret != 0) {
		/*
		 * ret != 0 here means that we didn't get to handle_mid() thus
		 * server->smallbuf and server->bigbuf are still valid. We need
		 * to free next_buffer because it is not going to be used
		 * anywhere.
		 */
		if (next_is_large)
			(*klpe_free_rsp_buf)(CIFS_LARGE_BUFFER, next_buffer);
		else
			(*klpe_free_rsp_buf)(CIFS_SMALL_BUFFER, next_buffer);
	}

	return ret;
}

int
klpp_smb3_receive_transform(struct TCP_Server_Info *server,
		       struct mid_q_entry **mids, char **bufs, int *num_mids)
{
	char *buf = server->smallbuf;
	unsigned int pdu_length = server->pdu_size;
	struct smb2_transform_hdr *tr_hdr = (struct smb2_transform_hdr *)buf;
	unsigned int orig_len = le32_to_cpu(tr_hdr->OriginalMessageSize);

	if (pdu_length < sizeof(struct smb2_transform_hdr) +
						sizeof(struct smb2_hdr)) {
		klpr_cifs_server_dbg(VFS, "Transform message is too small (%u)\n",
			 pdu_length);
		(*klpe_cifs_reconnect)(server, true);
		return -ECONNABORTED;
	}

	if (pdu_length < orig_len + sizeof(struct smb2_transform_hdr)) {
		klpr_cifs_server_dbg(VFS, "Transform message is broken\n");
		(*klpe_cifs_reconnect)(server, true);
		return -ECONNABORTED;
	}

	/* TODO: add support for compounds containing READ. */
	if (pdu_length > (*klpe_CIFSMaxBufSize) + MAX_HEADER_SIZE(server)) {
		return klpr_receive_encrypted_read(server, &mids[0], num_mids);
	}

	return klpr_receive_encrypted_standard(server, mids, bufs, num_mids);
}



#include "livepatch_bsc1219078.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "cifs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "CIFSMaxBufSize", (void *)&klpe_CIFSMaxBufSize, "cifs" },
	{ "cifsFYI", (void *)&klpe_cifsFYI, "cifs" },
	{ "cifs_buf_get", (void *)&klpe_cifs_buf_get, "cifs" },
	{ "cifs_discard_remaining_data",
	  (void *)&klpe_cifs_discard_remaining_data, "cifs" },
	{ "cifs_handle_standard", (void *)&klpe_cifs_handle_standard, "cifs" },
	{ "cifs_read_from_socket", (void *)&klpe_cifs_read_from_socket,
	  "cifs" },
	{ "cifs_read_page_from_socket",
	  (void *)&klpe_cifs_read_page_from_socket, "cifs" },
	{ "cifs_reconnect", (void *)&klpe_cifs_reconnect, "cifs" },
	{ "cifs_small_buf_get", (void *)&klpe_cifs_small_buf_get, "cifs" },
	{ "decrypt_raw_data", (void *)&klpe_decrypt_raw_data, "cifs" },
	{ "decrypt_wq", (void *)&klpe_decrypt_wq, "cifs" },
	{ "free_rsp_buf", (void *)&klpe_free_rsp_buf, "cifs" },
	{ "handle_read_data", (void *)&klpe_handle_read_data, "cifs" },
	{ "smb2_decrypt_offload", (void *)&klpe_smb2_decrypt_offload, "cifs" },
	{ "smb2_find_mid", (void *)&klpe_smb2_find_mid, "cifs" },
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

int livepatch_bsc1219078_init(void)
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

void livepatch_bsc1219078_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
