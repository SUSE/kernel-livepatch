/*
 * livepatch_bsc1247240
 *
 * Fix for CVE-2025-38488, bsc#1247240
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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
#include <linux/scatterlist.h>
#include <linux/uuid.h>

#include <crypto/aead.h>

#include <uapi/linux/magic.h>

/* klp-ccp: from fs/smb/client/cifsfs.h */
#include <linux/hash.h>

/* klp-ccp: from fs/smb/client/cifsglob.h */
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inet.h>
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

#define SMB2_SIGNATURE_SIZE		16

#define SMB3_GCM128_CRYPTKEY_SIZE	16
#define SMB3_GCM256_CRYPTKEY_SIZE	32

#define SMB3_ENC_DEC_KEY_SIZE		32

#define SMB3_SIGN_KEY_SIZE		16

#define SMB3_AES_CCM_NONCE 11
#define SMB3_AES_GCM_NONCE 12

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

#define SMB2_ENCRYPTION_AES128_GCM	cpu_to_le16(0x0002)
#define SMB2_ENCRYPTION_AES256_CCM      cpu_to_le16(0x0003)
#define SMB2_ENCRYPTION_AES256_GCM      cpu_to_le16(0x0004)

/* klp-ccp: from include/net/sock.h */
#define _SOCK_H

/* klp-ccp: from include/linux/net.h */
#define _LINUX_NET_H

/* klp-ccp: from fs/smb/client/cifsglob.h */
#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

/* klp-ccp: from fs/smb/client/cifspdu.h */
#include <net/sock.h>
#include <asm/unaligned.h>

#define CIFS_CRYPTO_KEY_SIZE (8)

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

enum securityEnum {
	Unspecified = 0,	/* not specified */
	NTLMv2,			/* Legacy NTLM auth with NTLMv2 hash */
	RawNTLMSSP,		/* NTLMSSP without SPNEGO, NTLMv2 hash */
	Kerberos,		/* Kerberos via SPNEGO */
};

enum upcall_target_enum {
	UPTARGET_UNSPECIFIED, /* not specified, defaults to app */
	UPTARGET_MOUNT, /* upcall to the mount namespace */
	UPTARGET_APP, /* upcall to the application namespace which did the mount */
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

struct smb_rqst {
	struct kvec	*rq_iov;	/* array of kvecs */
	unsigned int	rq_nvec;	/* number of kvecs in array */
	size_t		rq_iter_size;	/* Amount of data in ->rq_iter */
	struct iov_iter	rq_iter;	/* Data iterator */
	struct xarray	rq_buffer;	/* Page buffer for encryption */
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
	unsigned int	retrans;
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
	enum upcall_target_enum upcall_target; /* what upcall target was specified? */
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
	struct nls_table *local_nls;
};

extern spinlock_t		cifs_tcp_ses_lock;

static inline int cifs_get_num_sgs(const struct smb_rqst *rqst,
				   int num_rqst,
				   const u8 *sig)
{
	unsigned int len, skip;
	unsigned int nents = 0;
	unsigned long addr;
	int i, j;

	/*
	 * The first rqst has a transform header where the first 20 bytes are
	 * not part of the encrypted blob.
	 */
	skip = 20;

	/* Assumes the first rqst has a transform header as the first iov.
	 * I.e.
	 * rqst[0].rq_iov[0]  is transform header
	 * rqst[0].rq_iov[1+] data to be encrypted/decrypted
	 * rqst[1+].rq_iov[0+] data to be encrypted/decrypted
	 */
	for (i = 0; i < num_rqst; i++) {
		/* We really don't want a mixture of pinned and unpinned pages
		 * in the sglist.  It's hard to keep track of which is what.
		 * Instead, we convert to a BVEC-type iterator higher up.
		 */
		if (WARN_ON_ONCE(user_backed_iter(&rqst[i].rq_iter)))
			return -EIO;

		/* We also don't want to have any extra refs or pins to clean
		 * up in the sglist.
		 */
		if (WARN_ON_ONCE(iov_iter_extract_will_pin(&rqst[i].rq_iter)))
			return -EIO;

		for (j = 0; j < rqst[i].rq_nvec; j++) {
			struct kvec *iov = &rqst[i].rq_iov[j];

			addr = (unsigned long)iov->iov_base + skip;
			if (unlikely(is_vmalloc_addr((void *)addr))) {
				len = iov->iov_len - skip;
				nents += DIV_ROUND_UP(offset_in_page(addr) + len,
						      PAGE_SIZE);
			} else {
				nents++;
			}
			skip = 0;
		}
		nents += iov_iter_npages(&rqst[i].rq_iter, INT_MAX);
	}
	nents += DIV_ROUND_UP(offset_in_page(sig) + SMB2_SIGNATURE_SIZE, PAGE_SIZE);
	return nents;
}

static inline void cifs_sg_set_buf(struct sg_table *sgtable,
				   const void *buf,
				   unsigned int buflen)
{
	unsigned long addr = (unsigned long)buf;
	unsigned int off = offset_in_page(addr);

	addr &= PAGE_MASK;
	if (unlikely(is_vmalloc_addr((void *)addr))) {
		do {
			unsigned int len = min_t(unsigned int, buflen, PAGE_SIZE - off);

			sg_set_page(&sgtable->sgl[sgtable->nents++],
				    vmalloc_to_page((void *)addr), len, off);

			off = 0;
			addr += PAGE_SIZE;
			buflen -= len;
		} while (buflen);
	} else {
		sg_set_page(&sgtable->sgl[sgtable->nents++],
			    virt_to_page(addr), buflen, off);
	}
}

/* klp-ccp: from include/linux/nls.h */
#define _LINUX_NLS_H

/* klp-ccp: from fs/smb/client/cifsproto.h */
#include <linux/nls.h>
#include <linux/ctype.h>

/* klp-ccp: from fs/smb/client/trace.h */
#if !defined(_CIFS_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>
#include <linux/net.h>
#include <linux/inet.h>
#include "klp_trace.h"
KLPR_TRACE_EVENT(cifs, smb3_ses_not_found,
    TP_PROTO(__u64  sesid),
    TP_ARGS(sesid)
)

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

#define CIFS_INFO	0x01

#define VFS 1
#define FYI 2
extern int cifsFYI;

#define NOISY 0

#define ONCE 8

#define cifs_server_dbg_func(ratefunc, type, fmt, ...)			\
do {									\
	spin_lock(&server->srv_lock);					\
	if ((type) & FYI && cifsFYI & CIFS_INFO) {			\
		pr_debug_ ## ratefunc("%s: \\\\%s " fmt,		\
				      __FILE__, server->hostname,	\
				      ##__VA_ARGS__);			\
	} else if ((type) & VFS) {					\
		pr_err_ ## ratefunc("VFS: \\\\%s " fmt,			\
				    server->hostname, ##__VA_ARGS__);	\
	} else if ((type) & NOISY && (NOISY != 0)) {			\
		pr_debug_ ## ratefunc("\\\\%s " fmt,			\
				      server->hostname, ##__VA_ARGS__);	\
	}								\
	spin_unlock(&server->srv_lock);					\
} while (0)

#define cifs_server_dbg(type, fmt, ...)					\
do {									\
	if ((type) & ONCE)						\
		cifs_server_dbg_func(once, type, fmt, ##__VA_ARGS__);	\
	else								\
		cifs_server_dbg_func(ratelimited, type, fmt,		\
				     ##__VA_ARGS__);			\
} while (0)

/* klp-ccp: from fs/smb/client/cifs_unicode.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/nls.h>

/* klp-ccp: from fs/smb/client/reparse.h */
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/uidgid.h>

/* klp-ccp: from fs/smb/client/smb2ops.c */
static void *smb2_aead_req_alloc(struct crypto_aead *tfm, const struct smb_rqst *rqst,
				 int num_rqst, const u8 *sig, u8 **iv,
				 struct aead_request **req, struct sg_table *sgt,
				 unsigned int *num_sgs, size_t *sensitive_size)
{
	unsigned int req_size = sizeof(**req) + crypto_aead_reqsize(tfm);
	unsigned int iv_size = crypto_aead_ivsize(tfm);
	unsigned int len;
	u8 *p;

	*num_sgs = cifs_get_num_sgs(rqst, num_rqst, sig);
	if (IS_ERR_VALUE((long)(int)*num_sgs))
		return ERR_PTR(*num_sgs);

	len = iv_size;
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += req_size;
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += array_size(*num_sgs, sizeof(struct scatterlist));
	*sensitive_size = len;

	p = kvzalloc(len, GFP_NOFS);
	if (!p)
		return ERR_PTR(-ENOMEM);

	*iv = (u8 *)PTR_ALIGN(p, crypto_aead_alignmask(tfm) + 1);
	*req = (struct aead_request *)PTR_ALIGN(*iv + iv_size,
						crypto_tfm_ctx_alignment());
	sgt->sgl = (struct scatterlist *)PTR_ALIGN((u8 *)*req + req_size,
						   __alignof__(struct scatterlist));
	return p;
}

static void *smb2_get_aead_req(struct crypto_aead *tfm, struct smb_rqst *rqst,
			       int num_rqst, const u8 *sig, u8 **iv,
			       struct aead_request **req, struct scatterlist **sgl,
			       size_t *sensitive_size)
{
	struct sg_table sgtable = {};
	unsigned int skip, num_sgs, i, j;
	ssize_t rc;
	void *p;

	p = smb2_aead_req_alloc(tfm, rqst, num_rqst, sig, iv, req, &sgtable,
				&num_sgs, sensitive_size);
	if (IS_ERR(p))
		return ERR_CAST(p);

	sg_init_marker(sgtable.sgl, num_sgs);

	/*
	 * The first rqst has a transform header where the
	 * first 20 bytes are not part of the encrypted blob.
	 */
	skip = 20;

	for (i = 0; i < num_rqst; i++) {
		struct iov_iter *iter = &rqst[i].rq_iter;
		size_t count = iov_iter_count(iter);

		for (j = 0; j < rqst[i].rq_nvec; j++) {
			cifs_sg_set_buf(&sgtable,
					rqst[i].rq_iov[j].iov_base + skip,
					rqst[i].rq_iov[j].iov_len - skip);

			/* See the above comment on the 'skip' assignment */
			skip = 0;
		}
		sgtable.orig_nents = sgtable.nents;

		rc = extract_iter_to_sg(iter, count, &sgtable,
					num_sgs - sgtable.nents, 0);
		iov_iter_revert(iter, rc);
		sgtable.orig_nents = sgtable.nents;
	}

	cifs_sg_set_buf(&sgtable, sig, SMB2_SIGNATURE_SIZE);
	sg_mark_end(&sgtable.sgl[sgtable.nents - 1]);
	*sgl = sgtable.sgl;
	return p;
}

static int
smb2_get_enc_key(struct TCP_Server_Info *server, __u64 ses_id, int enc, u8 *key)
{
	struct TCP_Server_Info *pserver;
	struct cifs_ses *ses;
	u8 *ses_enc_key;

	/* If server is a channel, select the primary channel */
	pserver = CIFS_SERVER_IS_CHAN(server) ? server->primary_server : server;

	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(ses, &pserver->smb_ses_list, smb_ses_list) {
		if (ses->Suid == ses_id) {
			spin_lock(&ses->ses_lock);
			ses_enc_key = enc ? ses->smb3encryptionkey :
				ses->smb3decryptionkey;
			memcpy(key, ses_enc_key, SMB3_ENC_DEC_KEY_SIZE);
			spin_unlock(&ses->ses_lock);
			spin_unlock(&cifs_tcp_ses_lock);
			return 0;
		}
	}
	spin_unlock(&cifs_tcp_ses_lock);

	klpr_trace_smb3_ses_not_found(ses_id);

	return -EAGAIN;
}

int
klpp_crypt_message(struct TCP_Server_Info *server, int num_rqst,
	      struct smb_rqst *rqst, int enc, struct crypto_aead *tfm)
{
	struct smb2_transform_hdr *tr_hdr =
		(struct smb2_transform_hdr *)rqst[0].rq_iov[0].iov_base;
	unsigned int assoc_data_len = sizeof(struct smb2_transform_hdr) - 20;
	int rc = 0;
	struct scatterlist *sg;
	u8 sign[SMB2_SIGNATURE_SIZE] = {};
	u8 key[SMB3_ENC_DEC_KEY_SIZE];
	struct aead_request *req;
	u8 *iv;
	DECLARE_CRYPTO_WAIT(wait);
	unsigned int crypt_len = le32_to_cpu(tr_hdr->OriginalMessageSize);
	void *creq;
	size_t sensitive_size;

	rc = smb2_get_enc_key(server, le64_to_cpu(tr_hdr->SessionId), enc, key);
	if (rc) {
		cifs_server_dbg(FYI, "%s: Could not get %scryption key. sid: 0x%llx\n", __func__,
			 enc ? "en" : "de", le64_to_cpu(tr_hdr->SessionId));
		return rc;
	}

	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
		rc = crypto_aead_setkey(tfm, key, SMB3_GCM256_CRYPTKEY_SIZE);
	else
		rc = crypto_aead_setkey(tfm, key, SMB3_GCM128_CRYPTKEY_SIZE);

	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set aead key %d\n", __func__, rc);
		return rc;
	}

	rc = crypto_aead_setauthsize(tfm, SMB2_SIGNATURE_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set authsize %d\n", __func__, rc);
		return rc;
	}

	creq = smb2_get_aead_req(tfm, rqst, num_rqst, sign, &iv, &req, &sg,
				 &sensitive_size);
	if (IS_ERR(creq))
		return PTR_ERR(creq);

	if (!enc) {
		memcpy(sign, &tr_hdr->Signature, SMB2_SIGNATURE_SIZE);
		crypt_len += SMB2_SIGNATURE_SIZE;
	}

	if ((server->cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
	    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
		memcpy(iv, (char *)tr_hdr->Nonce, SMB3_AES_GCM_NONCE);
	else {
		iv[0] = 3;
		memcpy(iv + 1, (char *)tr_hdr->Nonce, SMB3_AES_CCM_NONCE);
	}

	aead_request_set_tfm(req, tfm);
	aead_request_set_crypt(req, sg, sg, crypt_len, iv);
	aead_request_set_ad(req, assoc_data_len);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

	rc = crypto_wait_req(enc ? crypto_aead_encrypt(req)
				: crypto_aead_decrypt(req), &wait);

	if (!rc && enc)
		memcpy(&tr_hdr->Signature, sign, SMB2_SIGNATURE_SIZE);

	kvfree_sensitive(creq, sensitive_size);
	return rc;
}


#include "livepatch_bsc1247240.h"

#include <linux/livepatch.h>
extern typeof(cifsFYI) cifsFYI KLP_RELOC_SYMBOL(cifs, cifs, cifsFYI);
extern typeof(cifs_tcp_ses_lock) cifs_tcp_ses_lock
	 KLP_RELOC_SYMBOL(cifs, cifs, cifs_tcp_ses_lock);
