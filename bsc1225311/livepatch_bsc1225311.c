/*
 * livepatch_bsc1225311
 *
 * Fix for CVE-2024-35862, bsc#1225311
 *
 *  Upstream commit:
 *  63981561ffd2 ("smb: client: fix potential UAF in smb2_is_network_name_deleted()")
 *
 *  SLE12-SP5 commit:
 *  6bbd54b71c90b4aaf49642ce864b50ad305513e4
 *
 *  SLE15-SP2 and -SP3 commit:
 *  8a40236696f1299f3021b83dbb96fb042ae4c533
 *
 *  SLE15-SP4 and -SP5 commit:
 *  aa75c0033201c4fbf52b9145a5e02f221b72cb64
 *
 *  SLE15-SP6 commit:
 *  6632102f196d048fce39ae5ef8876d6ad6b6dfa8
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


/* klp-ccp: from fs/smb/client/smb2ops.c */
#include <linux/pagemap.h>

/* klp-ccp: from include/linux/scatterlist.h */
#define _LINUX_SCATTERLIST_H

/* klp-ccp: from fs/smb/client/smb2ops.c */
#include <linux/uuid.h>
#include <uapi/linux/magic.h>
/* klp-ccp: from fs/smb/client/cifsfs.h */
#include <linux/hash.h>
/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <linux/in.h>

/* klp-ccp: from include/linux/inet.h */
#define _LINUX_INET_H

/* klp-ccp: from include/linux/ctype.h */
#define _LINUX_CTYPE_H

/* klp-ccp: from include/linux/inet.h */
#define INET6_ADDRSTRLEN	(48)

/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/workqueue.h>

/* klp-ccp: from include/uapi/linux/utsname.h */
#define __NEW_UTS_LEN 64

/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <linux/sched/mm.h>
/* klp-ccp: from fs/smb/client/cifs_fs_sb.h */
#include <linux/rbtree.h>

/* klp-ccp: from include/asm-generic/unaligned.h */
#define __ASM_GENERIC_UNALIGNED_H

/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <uapi/linux/cifs/cifs_mount.h>

/* klp-ccp: from fs/smb/common/smb2pdu.h */
#define NUMBER_OF_SMB2_COMMANDS	0x0013

#define SMB3_ENC_DEC_KEY_SIZE		32

#define SMB3_SIGN_KEY_SIZE		16

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

#define SMB2_CLIENT_GUID_SIZE		16

#define SMB2_PREAUTH_HASH_SIZE 64

/* klp-ccp: from include/net/sock.h */
#define _SOCK_H

/* klp-ccp: from include/linux/net.h */
#define _LINUX_NET_H

/* klp-ccp: from fs/smb/client/cifsglob.h */
#define MAX_TREE_SIZE (2 + CIFS_NI_MAXHOST + 1 + CIFS_MAX_SHARE_LEN + 1)

#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

/* klp-ccp: from fs/smb/client/cifspdu.h */
#include <net/sock.h>
#include <asm/unaligned.h>

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

/* klp-ccp: from fs/smb/client/cifsglob.h */
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

extern spinlock_t		cifs_tcp_ses_lock;

/* klp-ccp: from include/linux/nls.h */
#define _LINUX_NLS_H

/* klp-ccp: from fs/smb/client/cifsproto.h */
#include <linux/nls.h>
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

/* klp-ccp: from fs/smb/client/cifs_debug.h */
#undef pr_fmt
#define pr_fmt(fmt) "CIFS: " fmt

/* klp-ccp: from fs/smb/client/cifs_unicode.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/nls.h>

/* klp-ccp: from fs/smb/client/smb2status.h */
#define STATUS_NETWORK_NAME_DELETED cpu_to_le32(0xC00000C9)

/* klp-ccp: from fs/smb/client/smb2ops.c */
static inline bool klpp_cifs_ses_exiting(struct cifs_ses *ses)
{
	bool ret;

	spin_lock(&ses->ses_lock);
	ret = ses->ses_status == SES_EXITING;
	spin_unlock(&ses->ses_lock);
	return ret;
}

bool klpp_smb2_is_network_name_deleted(char *buf, struct TCP_Server_Info *server)
{
	struct smb2_hdr *shdr = (struct smb2_hdr *)buf;
	struct TCP_Server_Info *pserver;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;

	if (shdr->Status != STATUS_NETWORK_NAME_DELETED)
		return false;

	/* If server is a channel, select the primary channel */
	pserver = CIFS_SERVER_IS_CHAN(server) ? server->primary_server : server;

	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(ses, &pserver->smb_ses_list, smb_ses_list) {
		if (klpp_cifs_ses_exiting(ses))
			continue;
		list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
			if (tcon->tid == le32_to_cpu(shdr->Id.SyncId.TreeId)) {
				spin_lock(&tcon->tc_lock);
				tcon->need_reconnect = true;
				spin_unlock(&tcon->tc_lock);
				spin_unlock(&cifs_tcp_ses_lock);
				pr_warn_once("Server share %s deleted.\n",
					     tcon->tree_name);
				return true;
			}
		}
	}
	spin_unlock(&cifs_tcp_ses_lock);

	return false;
}


#include "livepatch_bsc1225311.h"
#include <linux/livepatch.h>

extern typeof(cifs_tcp_ses_lock) cifs_tcp_ses_lock
	 KLP_RELOC_SYMBOL(cifs, cifs, cifs_tcp_ses_lock);
