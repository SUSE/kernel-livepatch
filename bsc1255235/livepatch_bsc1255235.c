/*
 * livepatch_bsc1255235
 *
 * Fix for CVE-2023-53794, bsc#1255235
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


/* klp-ccp: from fs/cifs/smb2pdu.c */
#include <linux/fs.h>
#include <linux/kernel.h>

#include <linux/task_io_accounting_ops.h>
#include <linux/uaccess.h>
#include <linux/uuid.h>
#include <linux/pagemap.h>
#include <linux/xattr.h>

/* klp-ccp: from fs/cifs/smb2pdu.h */
#include <net/sock.h>

#define SMB2_TREE_CONNECT_HE	0x0003
#define SMB2_TREE_DISCONNECT_HE	0x0004 /* trivial req/resp */
#define SMB2_CREATE_HE		0x0005
#define SMB2_CLOSE_HE		0x0006
#define SMB2_FLUSH_HE		0x0007 /* trivial resp */
#define SMB2_READ_HE		0x0008
#define SMB2_WRITE_HE		0x0009
#define SMB2_LOCK_HE		0x000A
#define SMB2_IOCTL_HE		0x000B
#define SMB2_CANCEL_HE		0x000C

#define SMB2_QUERY_DIRECTORY_HE	0x000E
#define SMB2_CHANGE_NOTIFY_HE	0x000F
#define SMB2_QUERY_INFO_HE	0x0010
#define SMB2_SET_INFO_HE	0x0011
#define SMB2_OPLOCK_BREAK_HE	0x0012

#define SMB2_TREE_CONNECT	cpu_to_le16(SMB2_TREE_CONNECT_HE)
#define SMB2_TREE_DISCONNECT	cpu_to_le16(SMB2_TREE_DISCONNECT_HE)
#define SMB2_CREATE		cpu_to_le16(SMB2_CREATE_HE)
#define SMB2_CLOSE		cpu_to_le16(SMB2_CLOSE_HE)
#define SMB2_FLUSH		cpu_to_le16(SMB2_FLUSH_HE)
#define SMB2_READ		cpu_to_le16(SMB2_READ_HE)
#define SMB2_WRITE		cpu_to_le16(SMB2_WRITE_HE)
#define SMB2_LOCK		cpu_to_le16(SMB2_LOCK_HE)
#define SMB2_IOCTL		cpu_to_le16(SMB2_IOCTL_HE)
#define SMB2_CANCEL		cpu_to_le16(SMB2_CANCEL_HE)

#define SMB2_QUERY_DIRECTORY	cpu_to_le16(SMB2_QUERY_DIRECTORY_HE)
#define SMB2_CHANGE_NOTIFY	cpu_to_le16(SMB2_CHANGE_NOTIFY_HE)
#define SMB2_QUERY_INFO		cpu_to_le16(SMB2_QUERY_INFO_HE)
#define SMB2_SET_INFO		cpu_to_le16(SMB2_SET_INFO_HE)
#define SMB2_OPLOCK_BREAK	cpu_to_le16(SMB2_OPLOCK_BREAK_HE)

#define SMB2_INTERNAL_CMD	cpu_to_le16(0xFFFF)

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
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>

/* klp-ccp: from fs/cifs/cifs_fs_sb.h */
#include <linux/rbtree.h>

/* klp-ccp: from fs/cifs/cifsglob.h */
#include <uapi/linux/cifs/cifs_mount.h>

#define MAX_TREE_SIZE (2 + CIFS_NI_MAXHOST + 1 + CIFS_MAX_SHARE_LEN + 1)

#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

#define SERVER_NAME_LENGTH 80
#define SERVER_NAME_LEN_WITH_NULL     (SERVER_NAME_LENGTH + 1)

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

/* klp-ccp: from fs/cifs/cifsglob.h */
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

static spinlock_t		(*klpe_cifs_tcp_ses_lock);

static atomic_t (*klpe_tconInfoReconnectCount);

static struct workqueue_struct *(*klpe_cifsiod_wq);

/* klp-ccp: from fs/cifs/cifsproto.h */
#include <linux/nls.h>

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

static void (*klpe_cifs_mark_open_files_invalid)(struct cifs_tcon *tcon);
static void (*klpe_cifs_reopen_persistent_handles)(struct cifs_tcon *tcon);

static void (*klpe_cifs_put_tcp_session)(struct TCP_Server_Info *server,
				 int from_reconnect);
static void (*klpe_cifs_put_tcon)(struct cifs_tcon *tcon);

static int (*klpe_cifs_tree_connect)(const unsigned int xid, struct cifs_tcon *tcon,
			     const struct nls_table *nlsc);

static int (*klpe_cifs_negotiate_protocol)(const unsigned int xid,
				   struct cifs_ses *ses);
static int (*klpe_cifs_setup_session)(const unsigned int xid, struct cifs_ses *ses,
			      struct nls_table *nls_info);

static void (*klpe_cifs_put_smb_ses)(struct cifs_ses *ses);

static int (*klpe_cifs_wait_for_server_reconnect)(struct TCP_Server_Info *server, bool retry);

/* klp-ccp: from fs/cifs/smb2proto.h */
#include <linux/nls.h>

void klpp_smb2_reconnect_server(struct work_struct *work);

/* klp-ccp: from fs/cifs/cifs_unicode.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/nls.h>

/* klp-ccp: from fs/cifs/cifs_debug.h */
static int (*klpe_cifsFYI);

#define CIFS_INFO       0x01
#define CIFS_RC         0x02
#define CIFS_TIMER      0x04

#define FYI 2
#define ONCE 8
#define VFS 1
#define FYI 2
#ifdef CONFIG_CIFS_DEBUG2
#define NOISY 4
#else
#define NOISY 0
#endif
#define ONCE 8

/* information message: e.g., configuration, major event */
#define cifs_dbg_func(ratefunc, type, fmt, ...)                 \
do {                                                            \
        if ((type) & FYI && (*klpe_cifsFYI) & CIFS_INFO) {      \
                pr_debug_ ## ratefunc("%s: "                    \
                                fmt, __FILE__, ##__VA_ARGS__);  \
        } else if ((type) & VFS) {                              \
                pr_err_ ## ratefunc("CIFS VFS: "                \
                                 fmt, ##__VA_ARGS__);           \
        } else if ((type) & NOISY && (NOISY != 0)) {            \
                pr_debug_ ## ratefunc(fmt, ##__VA_ARGS__);      \
        }                                                       \
} while (0)

#define cifs_dbg(type, fmt, ...) \
do {                                                    \
        if ((type) & ONCE)                              \
                cifs_dbg_func(once,                     \
                         type, fmt, ##__VA_ARGS__);     \
        else                                            \
                cifs_dbg_func(ratelimited,              \
                        type, fmt, ##__VA_ARGS__);      \
} while (0)

/* klp-ccp: from fs/cifs/smb2pdu.c */
static int
klpr_smb2_reconnect(__le16 smb2_command, struct cifs_tcon *tcon)
{
	int rc;
	struct nls_table *nls_codepage;
	struct cifs_ses *ses;
	struct TCP_Server_Info *server;

	/*
	 * SMB2s NegProt, SessSetup, Logoff do not have tcon yet so
	 * check for tcp and smb session status done differently
	 * for those three - in the calling routine.
	 */
	if (tcon == NULL)
		return 0;

	/*
	 * Need to also skip SMB2_IOCTL because it is used for checking nested dfs links in
	 * cifs_tree_connect().
	 */
	if (smb2_command == SMB2_TREE_CONNECT || smb2_command == SMB2_IOCTL)
		return 0;

	spin_lock(&tcon->tc_lock);
	if (tcon->tidStatus == CifsExiting) {
		/*
		 * only tree disconnect, open, and write,
		 * (and ulogoff which does not have tcon)
		 * are allowed as we start force umount.
		 */
		if ((smb2_command != SMB2_WRITE) &&
		   (smb2_command != SMB2_CREATE) &&
		   (smb2_command != SMB2_TREE_DISCONNECT)) {
			spin_unlock(&tcon->tc_lock);
			cifs_dbg(FYI, "can not send cmd %d while umounting\n",
				 smb2_command);
			return -ENODEV;
		}
	}
	spin_unlock(&tcon->tc_lock);

	if (!tcon->ses)
		return -EIO;

	spin_lock(&tcon->ses->ses_lock);
	if ((tcon->ses->status == CifsExiting) || (!tcon->ses->server)) {
		spin_unlock(&tcon->ses->ses_lock);
		return -EIO;
	}
	spin_unlock(&tcon->ses->ses_lock);

	ses = tcon->ses;
	server = ses->server;

	spin_lock(&server->srv_lock);
	if (server->tcpStatus == CifsNeedReconnect) {
		/*
		 * Return to caller for TREE_DISCONNECT and LOGOFF and CLOSE
		 * here since they are implicitly done when session drops.
		 */
		switch (smb2_command) {
		/*
		 * BB Should we keep oplock break and add flush to exceptions?
		 */
		case SMB2_TREE_DISCONNECT:
		case SMB2_CANCEL:
		case SMB2_CLOSE:
		case SMB2_OPLOCK_BREAK:
			spin_unlock(&server->srv_lock);
			return -EAGAIN;
		}
	}
	spin_unlock(&server->srv_lock);

	rc = (*klpe_cifs_wait_for_server_reconnect)(server, tcon->retry);
	if (rc)
		return rc;

	if (!tcon->ses->need_reconnect && !tcon->need_reconnect)
		return 0;

	nls_codepage = load_nls_default();

	/*
	 * need to prevent multiple threads trying to simultaneously reconnect
	 * the same SMB session
	 */
	mutex_lock(&tcon->ses->session_mutex);

	/*
	 * Recheck after acquire mutex. If another thread is negotiating
	 * and the server never sends an answer the socket will be closed
	 * and tcpStatus set to reconnect.
	 */
	spin_lock(&server->srv_lock);
	if (server->tcpStatus == CifsNeedReconnect) {
		rc = -EHOSTDOWN;
		spin_unlock(&server->srv_lock);
		mutex_unlock(&tcon->ses->session_mutex);
		goto out;
	}
	spin_unlock(&server->srv_lock);

	rc = (*klpe_cifs_negotiate_protocol)(0, tcon->ses);
	if (!rc && tcon->ses->need_reconnect) {
		rc = (*klpe_cifs_setup_session)(0, tcon->ses, nls_codepage);
		if ((rc == -EACCES) && !tcon->retry) {
			rc = -EHOSTDOWN;
			mutex_unlock(&tcon->ses->session_mutex);
			goto failed;
		} else if (rc) {
			mutex_unlock(&ses->session_mutex);
			goto out;
		}
	}
	if (rc || !tcon->need_reconnect) {
		mutex_unlock(&tcon->ses->session_mutex);
		goto out;
	}

	(*klpe_cifs_mark_open_files_invalid)(tcon);
	if (tcon->use_persistent)
		tcon->need_reopen_files = true;

	rc = (*klpe_cifs_tree_connect)(0, tcon, nls_codepage);
	mutex_unlock(&tcon->ses->session_mutex);

	cifs_dbg(FYI, "reconnect tcon rc = %d\n", rc);
	if (rc) {
		/* If sess reconnected but tcon didn't, something strange ... */
		printk_once(KERN_WARNING "reconnect tcon failed rc = %d\n", rc);
		goto out;
	}

	if (smb2_command != SMB2_INTERNAL_CMD)
		mod_delayed_work((*klpe_cifsiod_wq), &server->reconnect, 0);

	atomic_inc(&(*klpe_tconInfoReconnectCount));
out:
	/*
	 * Check if handle based operation so we know whether we can continue
	 * or not without returning to caller to reset file handle.
	 */
	/*
	 * BB Is flush done by server on drop of tcp session? Should we special
	 * case it and skip above?
	 */
	switch (smb2_command) {
	case SMB2_FLUSH:
	case SMB2_READ:
	case SMB2_WRITE:
	case SMB2_LOCK:
	case SMB2_IOCTL:
	case SMB2_QUERY_DIRECTORY:
	case SMB2_CHANGE_NOTIFY:
	case SMB2_QUERY_INFO:
	case SMB2_SET_INFO:
		rc = -EAGAIN;
	}
failed:
	unload_nls(nls_codepage);
	return rc;
}


void klpp_smb2_reconnect_server(struct work_struct *work)
{
	struct TCP_Server_Info *server = container_of(work,
					struct TCP_Server_Info, reconnect.work);
	struct cifs_ses *ses;
	struct cifs_tcon *tcon, *tcon2;
	struct list_head tmp_list;
	int tcon_exist = false;
	int rc;
	int resched = false;


	/* Prevent simultaneous reconnects that can corrupt tcon->rlist list */
	mutex_lock(&server->reconnect_mutex);

	INIT_LIST_HEAD(&tmp_list);
	cifs_dbg(FYI, "Need negotiate, reconnecting tcons\n");

	spin_lock(&(*klpe_cifs_tcp_ses_lock));
	list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
		spin_lock(&ses->ses_lock);
		if (ses->status == CifsExiting) {
			spin_unlock(&ses->ses_lock);
			continue;
		}
		spin_unlock(&ses->ses_lock);

		list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
			if (tcon->need_reconnect || tcon->need_reopen_files) {
				tcon->tc_count++;
				list_add_tail(&tcon->rlist, &tmp_list);
				tcon_exist = true;
			}
		}
		/*
		 * IPC has the same lifetime as its session and uses its
		 * refcount.
		 */
		if (ses->tcon_ipc && ses->tcon_ipc->need_reconnect) {
			list_add_tail(&ses->tcon_ipc->rlist, &tmp_list);
			tcon_exist = true;
			ses->ses_count++;
		}
	}
	/*
	 * Get the reference to server struct to be sure that the last call of
	 * cifs_put_tcon() in the loop below won't release the server pointer.
	 */
	if (tcon_exist)
		server->srv_count++;

	spin_unlock(&(*klpe_cifs_tcp_ses_lock));

	list_for_each_entry_safe(tcon, tcon2, &tmp_list, rlist) {
		rc = klpr_smb2_reconnect(SMB2_INTERNAL_CMD, tcon);
		if (!rc)
			(*klpe_cifs_reopen_persistent_handles)(tcon);
		else
			resched = true;
		list_del_init(&tcon->rlist);
		if (tcon->ipc)
			(*klpe_cifs_put_smb_ses)(tcon->ses);
		else
			(*klpe_cifs_put_tcon)(tcon);
	}

	cifs_dbg(FYI, "Reconnecting tcons finished\n");
	if (resched)
		queue_delayed_work((*klpe_cifsiod_wq), &server->reconnect, 2 * HZ);
	mutex_unlock(&server->reconnect_mutex);

	/* now we can safely release srv struct */
	if (tcon_exist)
		(*klpe_cifs_put_tcp_session)(server, 1);
}


#include "livepatch_bsc1255235.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "cifs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "cifsFYI", (void *)&klpe_cifsFYI, "cifs" },
	{ "cifs_mark_open_files_invalid",
	  (void *)&klpe_cifs_mark_open_files_invalid, "cifs" },
	{ "cifs_negotiate_protocol", (void *)&klpe_cifs_negotiate_protocol,
	  "cifs" },
	{ "cifs_put_smb_ses", (void *)&klpe_cifs_put_smb_ses, "cifs" },
	{ "cifs_put_tcon", (void *)&klpe_cifs_put_tcon, "cifs" },
	{ "cifs_put_tcp_session", (void *)&klpe_cifs_put_tcp_session, "cifs" },
	{ "cifs_reopen_persistent_handles",
	  (void *)&klpe_cifs_reopen_persistent_handles, "cifs" },
	{ "cifs_setup_session", (void *)&klpe_cifs_setup_session, "cifs" },
	{ "cifs_tcp_ses_lock", (void *)&klpe_cifs_tcp_ses_lock, "cifs" },
	{ "cifs_tree_connect", (void *)&klpe_cifs_tree_connect, "cifs" },
	{ "cifs_wait_for_server_reconnect",
	  (void *)&klpe_cifs_wait_for_server_reconnect, "cifs" },
	{ "cifsiod_wq", (void *)&klpe_cifsiod_wq, "cifs" },
	{ "tconInfoReconnectCount", (void *)&klpe_tconInfoReconnectCount,
	  "cifs" },
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

int livepatch_bsc1255235_init(void)
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

void livepatch_bsc1255235_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
