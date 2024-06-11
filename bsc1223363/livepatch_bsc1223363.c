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

/* klp-ccp: from include/uapi/linux/utsname.h */
#define __NEW_UTS_LEN 64

/* klp-ccp: from fs/cifs/cifs_fs_sb.h */
#include <linux/rbtree.h>
/* klp-ccp: from fs/cifs/cifsglob.h */
#include <uapi/linux/cifs/cifs_mount.h>

/* klp-ccp: from fs/smbfs_common/smb2pdu.h */
#define NUMBER_OF_SMB2_COMMANDS	0x0013

#define SMB3_ENC_DEC_KEY_SIZE		32

#define SMB3_SIGN_KEY_SIZE		16

#define SMB2_CLIENT_GUID_SIZE		16

#define SMB2_PREAUTH_HASH_SIZE 64

/* klp-ccp: from include/net/sock.h */
#define _SOCK_H

/* klp-ccp: from fs/cifs/smb2pdu.h */
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

/* klp-ccp: from fs/cifs/cifsglob.h */
#define CIFS_PORT 445

#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

/* klp-ccp: from fs/cifs/cifspdu.h */
#include <net/sock.h>

#define CIFS_CRYPTO_KEY_SIZE (8)

/* klp-ccp: from fs/cifs/cifsglob.h */
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
	struct delayed_work	resolve; /* dns resolution workqueue job */
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
};

struct cifs_server_iface {
	struct list_head iface_head;
	struct kref refcount;
	size_t speed;
	unsigned int rdma_capable : 1;
	unsigned int rss_capable : 1;
	unsigned int is_active : 1; /* unset if non existent */
	struct sockaddr_storage sockaddr;
};

static inline void
release_iface(struct kref *ref)
{
	struct cifs_server_iface *iface = container_of(ref,
						       struct cifs_server_iface,
						       refcount);
	list_del_init(&iface->iface_head);
	kfree(iface);
}

static inline int
iface_cmp(struct cifs_server_iface *a, struct cifs_server_iface *b)
{
	int cmp_ret = 0;

	WARN_ON(!a || !b);
	if (a->speed == b->speed) {
		if (a->rdma_capable == b->rdma_capable) {
			if (a->rss_capable == b->rss_capable) {
				cmp_ret = memcmp(&a->sockaddr, &b->sockaddr,
						 sizeof(a->sockaddr));
				if (!cmp_ret)
					return 0;
				else if (cmp_ret > 0)
					return 1;
				else
					return -1;
			} else if (a->rss_capable > b->rss_capable)
				return 1;
			else
				return -1;
		} else if (a->rdma_capable > b->rdma_capable)
			return 1;
		else
			return -1;
	} else if (a->speed > b->speed)
		return 1;
	else
		return -1;
}

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

/* klp-ccp: from include/linux/nls.h */
#define _LINUX_NLS_H

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

/* klp-ccp: from fs/cifs/cifs_debug.h */
static int (*klpe_cifsFYI);

#define CIFS_INFO	0x01
#define VFS 1
#define FYI 2

#define NOISY 0
#define ONCE 8
#define cifs_dbg_func(ratefunc, type, fmt, ...)				\
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
		cifs_dbg_func(once, type, fmt, ##__VA_ARGS__);		\
	else								\
		cifs_dbg_func(ratelimited, type, fmt, ##__VA_ARGS__);	\
} while (0)

/* klp-ccp: from fs/cifs/cifs_unicode.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/nls.h>

/* klp-ccp: from fs/cifs/smb2ops.c */
int
klpp_parse_server_interfaces(struct network_interface_info_ioctl_rsp *buf,
			size_t buf_len, struct cifs_ses *ses, bool in_mount)
{
	struct network_interface_info_ioctl_rsp *p;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	struct iface_info_ipv4 *p4;
	struct iface_info_ipv6 *p6;
	struct cifs_server_iface *info = NULL, *iface = NULL, *niface = NULL;
	struct cifs_server_iface tmp_iface;
	ssize_t bytes_left;
	size_t next = 0;
	int nb_iface = 0;
	int rc = 0, ret = 0;

	bytes_left = buf_len;
	p = buf;

	spin_lock(&ses->iface_lock);
	/*
	 * Go through iface_list and do kref_put to remove
	 * any unused ifaces. ifaces in use will be removed
	 * when the last user calls a kref_put on it
	 */
	list_for_each_entry_safe(iface, niface, &ses->iface_list,
				 iface_head) {
		iface->is_active = 0;
		kref_put(&iface->refcount, release_iface);
		ses->iface_count--;
	}
	spin_unlock(&ses->iface_lock);

	/*
	 * Samba server e.g. can return an empty interface list in some cases,
	 * which would only be a problem if we were requesting multichannel
	 */
	if (bytes_left == 0) {
		/* avoid spamming logs every 10 minutes, so log only in mount */
		if ((ses->chan_max > 1) && in_mount)
			cifs_dbg(VFS,
				 "multichannel not available\n"
				 "Empty network interface list returned by server %s\n",
				 ses->server->hostname);
		rc = -EINVAL;
		goto out;
	}

	while (bytes_left >= (ssize_t)sizeof(*p)) {
		memset(&tmp_iface, 0, sizeof(tmp_iface));
		tmp_iface.speed = le64_to_cpu(p->LinkSpeed);
		tmp_iface.rdma_capable = le32_to_cpu(p->Capability & RDMA_CAPABLE) ? 1 : 0;
		tmp_iface.rss_capable = le32_to_cpu(p->Capability & RSS_CAPABLE) ? 1 : 0;

		switch (p->Family) {
		/*
		 * The kernel and wire socket structures have the same
		 * layout and use network byte order but make the
		 * conversion explicit in case either one changes.
		 */
		case INTERNETWORK:
			addr4 = (struct sockaddr_in *)&tmp_iface.sockaddr;
			p4 = (struct iface_info_ipv4 *)p->Buffer;
			addr4->sin_family = AF_INET;
			memcpy(&addr4->sin_addr, &p4->IPv4Address, 4);

			/* [MS-SMB2] 2.2.32.5.1.1 Clients MUST ignore these */
			addr4->sin_port = cpu_to_be16(CIFS_PORT);

			cifs_dbg(FYI, "%s: ipv4 %pI4\n", __func__,
				 &addr4->sin_addr);
			break;
		case INTERNETWORKV6:
			addr6 =	(struct sockaddr_in6 *)&tmp_iface.sockaddr;
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

		/*
		 * The iface_list is assumed to be sorted by speed.
		 * Check if the new interface exists in that list.
		 * NEVER change iface. it could be in use.
		 * Add a new one instead
		 */
		spin_lock(&ses->iface_lock);
		iface = niface = NULL;
		list_for_each_entry_safe(iface, niface, &ses->iface_list,
					 iface_head) {
			ret = iface_cmp(iface, &tmp_iface);
			if (!ret) {
				/* just get a ref so that it doesn't get picked/freed */
				iface->is_active = 1;
				kref_get(&iface->refcount);
				ses->iface_count++;
				spin_unlock(&ses->iface_lock);
				goto next_iface;
			} else if (ret < 0) {
				/* all remaining ifaces are slower */
				kref_get(&iface->refcount);
				break;
			}
		}
		spin_unlock(&ses->iface_lock);

		/* no match. insert the entry in the list */
		info = kmalloc(sizeof(struct cifs_server_iface),
			       GFP_KERNEL);
		if (!info) {
			rc = -ENOMEM;
			goto out;
		}
		memcpy(info, &tmp_iface, sizeof(tmp_iface));

		/* add this new entry to the list */
		kref_init(&info->refcount);
		info->is_active = 1;

		cifs_dbg(FYI, "%s: adding iface %zu\n", __func__, ses->iface_count);
		cifs_dbg(FYI, "%s: speed %zu bps\n", __func__, info->speed);
		cifs_dbg(FYI, "%s: capabilities 0x%08x\n", __func__,
			 le32_to_cpu(p->Capability));

		spin_lock(&ses->iface_lock);
		if (!list_entry_is_head(iface, &ses->iface_list, iface_head)) {
			list_add_tail(&info->iface_head, &iface->iface_head);
			kref_put(&iface->refcount, release_iface);
		} else
			list_add_tail(&info->iface_head, &ses->iface_list);

		ses->iface_count++;
		spin_unlock(&ses->iface_lock);
		ses->iface_last_update = jiffies;
next_iface:
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


	if (!ses->iface_count) {
		rc = -EINVAL;
		goto out;
	}

out:
	return rc;
}


#include "livepatch_bsc1223363.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "cifs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "cifsFYI", (void *)&klpe_cifsFYI, "cifs" },
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

int livepatch_bsc1223363_init(void)
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

void livepatch_bsc1223363_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
