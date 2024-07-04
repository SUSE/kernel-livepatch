/*
 * livepatch_bsc1223363
 *
 * Fix for CVE-2024-26828, bsc#1223363
 *
 *  Upstream commit:
 *  cffe487026be ("cifs: fix underflow in parse_server_interfaces()")
 *
 *  SLE12-SP5 commit:
 *  7164147edf5115edbb61413edc2011dcf9fe640a
 *
 *  SLE15-SP2 and -SP3 commit:
 *  8a48c12c0878719f9a5f45be5ea373cb2d809bc5
 *
 *  SLE15-SP4 and -SP5 commit:
 *  cade5483d97fc91b3e4f329b6fade430f49fbb11
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

/* klp-ccp: from fs/cifs/smb2ops.c */
#include <linux/pagemap.h>

/* klp-ccp: from fs/cifs/smb2ops.c */
#include <linux/uuid.h>
#include <crypto/aead.h>
#include <uapi/linux/magic.h>
/* klp-ccp: from fs/cifs/cifsfs.h */
#include <linux/hash.h>
/* klp-ccp: from fs/cifs/cifsglob.h */
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
/* klp-ccp: from fs/cifs/cifs_fs_sb.h */
#include <linux/rbtree.h>
/* klp-ccp: from fs/cifs/cifsglob.h */
#include <linux/scatterlist.h>
#include <uapi/linux/cifs/cifs_mount.h>

/* klp-ccp: from fs/cifs/smb2pdu.h */
#define NUMBER_OF_SMB2_COMMANDS	0x0013

#define SMB2_PREAUTH_HASH_SIZE 64

#define SMB2_OPLOCK_LEVEL_NONE		0x00

#define SMB2_LEASE_KEY_SIZE 16

#define RSS_CAPABLE	cpu_to_le32(0x00000001)
#define RDMA_CAPABLE	cpu_to_le32(0x00000002)

#define INTERNETWORK	cpu_to_le16(0x0002)
#define INTERNETWORKV6	cpu_to_le16(0x0017)

struct network_interface_info_ioctl_rsp {
	__le32 Next; /* next interface. zero if this is last one */
	__le32 IfIndex;
	__le32 Capability; /* RSS or RDMA Capable */
	__le32 Reserved;
	__le64 LinkSpeed;
	__le16 Family;
	__u8 Buffer[126];
} __packed;

struct iface_info_ipv4 {
	__be16 Port;
	__be32 IPv4Address;
	__be64 Reserved;
} __packed;

struct iface_info_ipv6 {
	__be16 Port;
	__be32 FlowInfo;
	__u8   IPv6Address[16];
	__be32 ScopeId;
} __packed;

#define NO_FILE_ID 0xFFFFFFFFFFFFFFFFULL /* general ioctls to srv not to file */

#define FS_VOLUME_INFORMATION		1 /* Query */

#define FS_DEVICE_INFORMATION		4 /* Query */
#define FS_ATTRIBUTE_INFORMATION	5 /* Query */

#define FS_SECTOR_SIZE_INFORMATION	11 /* SMB3 or later. Query */

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

struct create_posix_rsp;

/* klp-ccp: from fs/cifs/cifsglob.h */
#define CIFS_PORT 445

#define MAX_TREE_SIZE (2 + CIFS_NI_MAXHOST + 1 + CIFS_MAX_SHARE_LEN + 1)

#define SERVER_NAME_LENGTH 80
#define SERVER_NAME_LEN_WITH_NULL     (SERVER_NAME_LENGTH + 1)

/* klp-ccp: from fs/cifs/cifspdu.h */
#include <net/sock.h>
#include <asm/unaligned.h>

/* klp-ccp: from fs/cifs/smbfsctl.h */
#define FSCTL_QUERY_NETWORK_INTERFACE_INFO 0x001401FC /* BB add struct */

/* klp-ccp: from fs/cifs/cifspdu.h */
#define SMB3_SIGN_KEY_SIZE (16)

#define FILE_READ_ATTRIBUTES  0x00000080  /* Attributes associated with the   */

#define FILE_OPEN         0x00000001

#define CREATE_OPEN_BACKUP_INTENT 0x00004000

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

struct cifs_server_iface {
	size_t speed;
	unsigned int rdma_capable : 1;
	unsigned int rss_capable : 1;
	struct sockaddr_storage sockaddr;
};

struct cifs_ses {
	struct list_head smb_ses_list;
	struct list_head tcon_list;
	struct cifs_tcon *tcon_ipc;
	struct mutex session_mutex;
	struct TCP_Server_Info *server;	/* pointer to server info */
	int ses_count;		/* reference counter */
	enum statusEnum status;  /* updates protected by GlobalMid_Lock */
	unsigned overrideSecFlg;  /* if non-zero override global sec flags */
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

struct cifs_open_parms {
	struct cifs_tcon *tcon;
	struct cifs_sb_info *cifs_sb;
	int disposition;
	int desired_access;
	int create_options;
	const char *path;
	struct cifs_fid *fid;
	umode_t mode;
	bool reconnect:1;
};

struct cifs_fid {
	__u16 netfid;
	__u64 persistent_fid;	/* persist file id for smb2 */
	__u64 volatile_fid;	/* volatile file id for smb2 */
	__u8 lease_key[SMB2_LEASE_KEY_SIZE];	/* lease key for smb2 */
	__u8 create_guid[16];
	__u32 access;
	struct cifs_pending_open *pending_open;
	unsigned int epoch;
#ifdef CONFIG_CIFS_DEBUG2
#error "klp-ccp: non-taken branch"
#endif /* CIFS_DEBUG2 */
	bool purge_cache;
};

static unsigned int (*klpe_CIFSMaxBufSize);

/* klp-ccp: from include/linux/nls.h */
#define _LINUX_NLS_H

/* klp-ccp: from fs/cifs/smb2proto.h */
static int (*klpe_open_cached_dir)(unsigned int xid, struct cifs_tcon *tcon,
			   const char *path,
			   struct cifs_sb_info *cifs_sb,
			   struct cached_fid **cfid);

static void (*klpe_close_cached_dir)(struct cached_fid *cfid);

static int (*klpe_SMB2_open)(const unsigned int xid, struct cifs_open_parms *oparms,
		     __le16 *path, __u8 *oplock,
		     struct smb2_file_all_info *buf,
		     struct create_posix_rsp *posix,
		     struct kvec *err_iov, int *resp_buftype);

static int (*klpe_SMB2_ioctl)(const unsigned int xid, struct cifs_tcon *tcon,
		     u64 persistent_fid, u64 volatile_fid, u32 opcode,
		     char *in_data, u32 indatalen, u32 maxoutlen,
		     char **out_data, u32 *plen /* returned data len */);

static int (*klpe_SMB2_close)(const unsigned int xid, struct cifs_tcon *tcon,
		      u64 persistent_file_id, u64 volatile_file_id);

static int (*klpe_SMB2_QFS_attr)(const unsigned int xid, struct cifs_tcon *tcon,
			 u64 persistent_file_id, u64 volatile_file_id, int lvl);

/* klp-ccp: from fs/cifs/cifsproto.h */
#include <linux/nls.h>
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

static bool (*klpe_backup_cred)(struct cifs_sb_info *);

static inline int klpr_cifs_create_options(struct cifs_sb_info *cifs_sb, int options)
{
	if (cifs_sb && ((*klpe_backup_cred)(cifs_sb)))
		return options | CREATE_OPEN_BACKUP_INTENT;
	else
		return options;
}

/* klp-ccp: from fs/cifs/cifs_debug.h */
static int (*klpe_cifsFYI);

#define CIFS_INFO	0x01
#define VFS 1
#define FYI 2

#define NOISY 0
#define ONCE 8
#define cifs_dbg_func(ratefunc, type, fmt, ...)			\
do {								\
	if ((type) & FYI && (*klpe_cifsFYI) & CIFS_INFO) {		\
		pr_debug_ ## ratefunc("%s: "			\
				fmt, __FILE__, ##__VA_ARGS__);	\
	} else if ((type) & VFS) {				\
		pr_err_ ## ratefunc("CIFS VFS: "		\
				 fmt, ##__VA_ARGS__);		\
	} else if ((type) & NOISY && (NOISY != 0)) {		\
		pr_debug_ ## ratefunc(fmt, ##__VA_ARGS__);	\
	}							\
} while (0)
#define cifs_dbg(type, fmt, ...) \
do {							\
	if ((type) & ONCE)				\
		cifs_dbg_func(once,			\
			 type, fmt, ##__VA_ARGS__);	\
	else						\
		cifs_dbg_func(ratelimited,		\
			type, fmt, ##__VA_ARGS__);	\
} while (0)
#define cifs_tcon_dbg_func(ratefunc, type, fmt, ...)		\
do {								\
	const char *tn = "";					\
	if (tcon && tcon->treeName)				\
		tn = tcon->treeName;				\
	if ((type) & FYI && (*klpe_cifsFYI) & CIFS_INFO) {		\
		pr_debug_ ## ratefunc("%s: %s "	fmt,		\
			__FILE__, tn, ##__VA_ARGS__);		\
	} else if ((type) & VFS) {				\
		pr_err_ ## ratefunc("CIFS VFS: %s " fmt,	\
			tn, ##__VA_ARGS__);			\
	} else if ((type) & NOISY && (NOISY != 0)) {		\
		pr_debug_ ## ratefunc("%s " fmt,		\
			tn, ##__VA_ARGS__);			\
	}							\
} while (0)
#define cifs_tcon_dbg(type, fmt, ...)			\
do {							\
	if ((type) & ONCE)				\
		cifs_tcon_dbg_func(once,		\
			type, fmt, ##__VA_ARGS__);	\
	else						\
		cifs_tcon_dbg_func(ratelimited,	\
			type, fmt, ##__VA_ARGS__);	\
} while (0)

/* klp-ccp: from fs/cifs/cifs_unicode.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/nls.h>

/* klp-ccp: from fs/cifs/smb2ops.c */
static int
klpr_parse_server_interfaces(struct network_interface_info_ioctl_rsp *buf,
			size_t buf_len,
			struct cifs_server_iface **iface_list,
			size_t *iface_count)
{
	struct network_interface_info_ioctl_rsp *p;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	struct iface_info_ipv4 *p4;
	struct iface_info_ipv6 *p6;
	struct cifs_server_iface *info;
	ssize_t bytes_left;
	size_t next = 0;
	int nb_iface = 0;
	int rc = 0;

	*iface_list = NULL;
	*iface_count = 0;

	/*
	 * Fist pass: count and sanity check
	 */

	bytes_left = buf_len;
	p = buf;
	while (bytes_left >= sizeof(*p)) {
		nb_iface++;
		next = le32_to_cpu(p->Next);
		if (!next) {
			bytes_left -= sizeof(*p);
			break;
		}
		p = (struct network_interface_info_ioctl_rsp *)((u8 *)p+next);
		bytes_left -= next;
	}

	if (!nb_iface) {
		cifs_dbg(VFS, "%s: malformed interface info\n", __func__);
		rc = -EINVAL;
		goto out;
	}

	/* Azure rounds the buffer size up 8, to a 16 byte boundary */
	if ((bytes_left > 8) || p->Next)
		cifs_dbg(VFS, "%s: incomplete interface info\n", __func__);


	/*
	 * Second pass: extract info to internal structure
	 */

	*iface_list = kcalloc(nb_iface, sizeof(**iface_list), GFP_KERNEL);
	if (!*iface_list) {
		rc = -ENOMEM;
		goto out;
	}

	info = *iface_list;
	bytes_left = buf_len;
	p = buf;
	while (bytes_left >= (ssize_t)sizeof(*p)) {
		info->speed = le64_to_cpu(p->LinkSpeed);
		info->rdma_capable = le32_to_cpu(p->Capability & RDMA_CAPABLE) ? 1 : 0;
		info->rss_capable = le32_to_cpu(p->Capability & RSS_CAPABLE) ? 1 : 0;

		cifs_dbg(FYI, "%s: adding iface %zu\n", __func__, *iface_count);
		cifs_dbg(FYI, "%s: speed %zu bps\n", __func__, info->speed);
		cifs_dbg(FYI, "%s: capabilities 0x%08x\n", __func__,
			 le32_to_cpu(p->Capability));

		switch (p->Family) {
		/*
		 * The kernel and wire socket structures have the same
		 * layout and use network byte order but make the
		 * conversion explicit in case either one changes.
		 */
		case INTERNETWORK:
			addr4 = (struct sockaddr_in *)&info->sockaddr;
			p4 = (struct iface_info_ipv4 *)p->Buffer;
			addr4->sin_family = AF_INET;
			memcpy(&addr4->sin_addr, &p4->IPv4Address, 4);

			/* [MS-SMB2] 2.2.32.5.1.1 Clients MUST ignore these */
			addr4->sin_port = cpu_to_be16(CIFS_PORT);

			cifs_dbg(FYI, "%s: ipv4 %pI4\n", __func__,
				 &addr4->sin_addr);
			break;
		case INTERNETWORKV6:
			addr6 =	(struct sockaddr_in6 *)&info->sockaddr;
			p6 = (struct iface_info_ipv6 *)p->Buffer;
			addr6->sin6_family = AF_INET6;
			memcpy(&addr6->sin6_addr, &p6->IPv6Address, 16);

			/* [MS-SMB2] 2.2.32.5.1.2 Clients MUST ignore these */
			addr6->sin6_flowinfo = 0;
			addr6->sin6_scope_id = 0;
			addr6->sin6_port = cpu_to_be16(CIFS_PORT);

			cifs_dbg(FYI, "%s: ipv6 %pI6\n", __func__,
				 &addr6->sin6_addr);
			break;
		default:
			cifs_dbg(VFS,
				 "%s: skipping unsupported socket family\n",
				 __func__);
			goto next_iface;
		}

		(*iface_count)++;
		info++;
next_iface:
		next = le32_to_cpu(p->Next);
		if (!next)
			break;
		p = (struct network_interface_info_ioctl_rsp *)((u8 *)p+next);
		bytes_left -= next;
	}

	if (!*iface_count) {
		rc = -EINVAL;
		goto out;
	}

out:
	if (rc) {
		kfree(*iface_list);
		*iface_count = 0;
		*iface_list = NULL;
	}
	return rc;
}

static int
klpr_SMB3_request_interfaces(const unsigned int xid, struct cifs_tcon *tcon)
{
	int rc;
	unsigned int ret_data_len = 0;
	struct network_interface_info_ioctl_rsp *out_buf = NULL;
	struct cifs_server_iface *iface_list;
	size_t iface_count;
	struct cifs_ses *ses = tcon->ses;

	rc = (*klpe_SMB2_ioctl)(xid, tcon, NO_FILE_ID, NO_FILE_ID,
			FSCTL_QUERY_NETWORK_INTERFACE_INFO,
			NULL /* no data input */, 0 /* no data input */,
			(*klpe_CIFSMaxBufSize), (char **)&out_buf, &ret_data_len);
	if (rc == -EOPNOTSUPP) {
		cifs_dbg(FYI,
			 "server does not support query network interfaces\n");
		goto out;
	} else if (rc != 0) {
		cifs_tcon_dbg(VFS, "error %d on ioctl to get interface list\n", rc);
		goto out;
	}

	rc = klpr_parse_server_interfaces(out_buf, ret_data_len,
				     &iface_list, &iface_count);
	if (rc)
		goto out;

	spin_lock(&ses->iface_lock);
	kfree(ses->iface_list);
	ses->iface_list = iface_list;
	ses->iface_count = iface_count;
	ses->iface_last_update = jiffies;
	spin_unlock(&ses->iface_lock);

out:
	kfree(out_buf);
	return rc;
}

void
klpp_smb3_qfs_tcon(const unsigned int xid, struct cifs_tcon *tcon,
	      struct cifs_sb_info *cifs_sb)
{
	int rc;
	__le16 srch_path = 0; /* Null - open root of share */
	u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_open_parms oparms;
	struct cifs_fid fid;
	struct cached_fid *cfid = NULL;

	oparms.tcon = tcon;
	oparms.desired_access = FILE_READ_ATTRIBUTES;
	oparms.disposition = FILE_OPEN;
	oparms.create_options = klpr_cifs_create_options(cifs_sb, 0);
	oparms.fid = &fid;
	oparms.reconnect = false;

	rc = (*klpe_open_cached_dir)(xid, tcon, "", cifs_sb, &cfid);
	if (rc == 0)
		memcpy(&fid, cfid->fid, sizeof(struct cifs_fid));
	else
		rc = (*klpe_SMB2_open)(xid, &oparms, &srch_path, &oplock, NULL, NULL,
			       NULL, NULL);
	if (rc)
		return;

	klpr_SMB3_request_interfaces(xid, tcon);

	(*klpe_SMB2_QFS_attr)(xid, tcon, fid.persistent_fid, fid.volatile_fid,
			FS_ATTRIBUTE_INFORMATION);
	(*klpe_SMB2_QFS_attr)(xid, tcon, fid.persistent_fid, fid.volatile_fid,
			FS_DEVICE_INFORMATION);
	(*klpe_SMB2_QFS_attr)(xid, tcon, fid.persistent_fid, fid.volatile_fid,
			FS_VOLUME_INFORMATION);
	(*klpe_SMB2_QFS_attr)(xid, tcon, fid.persistent_fid, fid.volatile_fid,
			FS_SECTOR_SIZE_INFORMATION); /* SMB3 specific */
	if (cfid == NULL)
		(*klpe_SMB2_close)(xid, tcon, fid.persistent_fid, fid.volatile_fid);
	else
		(*klpe_close_cached_dir)(cfid);
}


#include "livepatch_bsc1223363.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "cifs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "CIFSMaxBufSize", (void *)&klpe_CIFSMaxBufSize, "cifs" },
	{ "SMB2_QFS_attr", (void *)&klpe_SMB2_QFS_attr, "cifs" },
	{ "SMB2_close", (void *)&klpe_SMB2_close, "cifs" },
	{ "SMB2_ioctl", (void *)&klpe_SMB2_ioctl, "cifs" },
	{ "SMB2_open", (void *)&klpe_SMB2_open, "cifs" },
	{ "backup_cred", (void *)&klpe_backup_cred, "cifs" },
	{ "cifsFYI", (void *)&klpe_cifsFYI, "cifs" },
	{ "close_cached_dir", (void *)&klpe_close_cached_dir, "cifs" },
	{ "open_cached_dir", (void *)&klpe_open_cached_dir, "cifs" },
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

int livepatch_bsc1223363_init(void)
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

void livepatch_bsc1223363_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
