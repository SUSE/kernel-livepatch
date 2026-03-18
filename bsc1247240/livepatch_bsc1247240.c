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


/* klp-ccp: from fs/cifs/smb2ops.c */
#include <linux/pagemap.h>
#include <linux/scatterlist.h>
#include <linux/uuid.h>
#include <crypto/aead.h>
#include <uapi/linux/magic.h>

/* klp-ccp: from fs/cifs/cifsfs.h */
#include <linux/hash.h>

/* klp-ccp: from fs/cifs/cifsglob.h */
#include <linux/in.h>

#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>

/* klp-ccp: from fs/cifs/cifs_fs_sb.h */
#include <linux/rbtree.h>

/* klp-ccp: from fs/cifs/cifsglob.h */
#include <uapi/linux/cifs/cifs_mount.h>

/* klp-ccp: from include/net/sock.h */
#define _SOCK_H

/* klp-ccp: from arch/x86/include/asm/unaligned.h */
#define _ASM_X86_UNALIGNED_H

/* klp-ccp: from fs/cifs/smb2pdu.h */
#define NUMBER_OF_SMB2_COMMANDS	0x0013

#define SMB3_AES128CCM_NONCE 11
#define SMB3_AES128GCM_NONCE 12

struct smb2_transform_hdr {
	__le32 ProtocolId;	/* 0xFD 'S' 'M' 'B' */
	__u8   Signature[16];
	__u8   Nonce[16];
	__le32 OriginalMessageSize;
	__u16  Reserved1;
	__le16 Flags; /* EncryptionAlgorithm for 3.0, enc enabled for 3.1.1 */
	__u64  SessionId;
} __packed;

#define SMB2_CLIENT_GUID_SIZE 16

#define SMB2_PREAUTH_HASH_SIZE 64

#define SMB2_ENCRYPTION_AES128_GCM	cpu_to_le16(0x0002)

/* klp-ccp: from fs/cifs/smb2glob.h */
#define SMB2_SIGNATURE_SIZE (16)

/* klp-ccp: from fs/cifs/cifsglob.h */
#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

#define SERVER_NAME_LENGTH 80
#define SERVER_NAME_LEN_WITH_NULL     (SERVER_NAME_LENGTH + 1)

/* klp-ccp: from fs/cifs/cifspdu.h */
#include <net/sock.h>
#include <asm/unaligned.h>

#define CIFS_CRYPTO_KEY_SIZE (8)

#define SMB3_SIGN_KEY_SIZE (16)

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

struct smb_rqst {
	struct kvec	*rq_iov;	/* array of kvecs */
	unsigned int	rq_nvec;	/* number of kvecs in array */
	struct page	**rq_pages;	/* pointer to array of page ptrs */
	unsigned int	rq_offset;	/* the offset to the 1st page */
	unsigned int	rq_npages;	/* number pages in array */
	unsigned int	rq_pagesz;	/* page size to use */
	unsigned int	rq_tailsz;	/* length of last page */
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

static spinlock_t		(*klpe_cifs_tcp_ses_lock);

static inline unsigned int cifs_get_num_sgs(const struct smb_rqst *rqst,
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
		nents += rqst[i].rq_npages;
	}
	nents += DIV_ROUND_UP(offset_in_page(sig) + SMB2_SIGNATURE_SIZE, PAGE_SIZE);
	return nents;
}

static inline struct scatterlist *cifs_sg_set_buf(struct scatterlist *sg,
						  const void *buf,
						  unsigned int buflen)
{
	unsigned long addr = (unsigned long)buf;
	unsigned int off = offset_in_page(addr);

	addr &= PAGE_MASK;
	if (unlikely(is_vmalloc_addr((void *)addr))) {
		do {
			unsigned int len = min_t(unsigned int, buflen, PAGE_SIZE - off);

			sg_set_page(sg++, vmalloc_to_page((void *)addr), len, off);

			off = 0;
			addr += PAGE_SIZE;
			buflen -= len;
		} while (buflen);
	} else {
		sg_set_page(sg++, virt_to_page(addr), buflen, off);
	}
	return sg;
}

/* klp-ccp: from include/linux/nls.h */
#define _LINUX_NLS_H

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

static void (*klpe_rqst_page_get_length)(const struct smb_rqst *rqst, unsigned int page,
			unsigned int *len, unsigned int *offset);

/* klp-ccp: from fs/cifs/cifs_debug.h */
#define CIFS_INFO	0x01

#define VFS 1
#define FYI 2
extern int cifsFYI;

#define NOISY 0

#define ONCE 8

#define cifs_server_dbg_func(ratefunc, type, fmt, ...)		\
do {								\
	const char *sn = "";					\
	if (server && server->hostname)				\
		sn = server->hostname;				\
	if ((type) & FYI && cifsFYI & CIFS_INFO) {		\
		pr_debug_ ## ratefunc("%s: \\\\%s "	fmt,	\
			__FILE__, sn, ##__VA_ARGS__);		\
	} else if ((type) & VFS) {				\
		pr_err_ ## ratefunc("CIFS VFS: \\\\%s " fmt,	\
			sn, ##__VA_ARGS__);			\
	} else if ((type) & NOISY && (NOISY != 0)) {		\
		pr_debug_ ## ratefunc("\\\\%s " fmt,		\
			sn, ##__VA_ARGS__);			\
	}							\
} while (0)

#define cifs_server_dbg(type, fmt, ...)			\
do {							\
	if ((type) & ONCE)				\
		cifs_server_dbg_func(once,		\
			type, fmt, ##__VA_ARGS__);	\
	else						\
		cifs_server_dbg_func(ratelimited,	\
			type, fmt, ##__VA_ARGS__);	\
} while (0)

/* klp-ccp: from fs/cifs/cifs_unicode.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/nls.h>

/* klp-ccp: from fs/cifs/smb2ops.c */
static void *smb2_aead_req_alloc(struct crypto_aead *tfm, const struct smb_rqst *rqst,
				 int num_rqst, const u8 *sig, u8 **iv,
				 struct aead_request **req, struct scatterlist **sgl,
				 unsigned int *num_sgs)
{
	unsigned int req_size = sizeof(**req) + crypto_aead_reqsize(tfm);
	unsigned int iv_size = crypto_aead_ivsize(tfm);
	unsigned int len;
	u8 *p;

	*num_sgs = cifs_get_num_sgs(rqst, num_rqst, sig);

	len = iv_size;
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += req_size;
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += *num_sgs * sizeof(**sgl);

	p = kmalloc(len, GFP_ATOMIC);
	if (!p)
		return NULL;

	*iv = (u8 *)PTR_ALIGN(p, crypto_aead_alignmask(tfm) + 1);
	*req = (struct aead_request *)PTR_ALIGN(*iv + iv_size,
						crypto_tfm_ctx_alignment());
	*sgl = (struct scatterlist *)PTR_ALIGN((u8 *)*req + req_size,
					       __alignof__(struct scatterlist));
	return p;
}

static void *klpr_smb2_get_aead_req(struct crypto_aead *tfm, const struct smb_rqst *rqst,
			       int num_rqst, const u8 *sig, u8 **iv,
			       struct aead_request **req, struct scatterlist **sgl)
{
	unsigned int off, len, skip;
	struct scatterlist *sg;
	unsigned int num_sgs;
	unsigned long addr;
	int i, j;
	void *p;

	p = smb2_aead_req_alloc(tfm, rqst, num_rqst, sig, iv, req, sgl, &num_sgs);
	if (!p)
		return NULL;

	sg_init_table(*sgl, num_sgs);
	sg = *sgl;

	/*
	 * The first rqst has a transform header where the
	 * first 20 bytes are not part of the encrypted blob.
	 */
	skip = 20;

	/* Assumes the first rqst has a transform header as the first iov.
	 * I.e.
	 * rqst[0].rq_iov[0]  is transform header
	 * rqst[0].rq_iov[1+] data to be encrypted/decrypted
	 * rqst[1+].rq_iov[0+] data to be encrypted/decrypted
	 */
	for (i = 0; i < num_rqst; i++) {
		for (j = 0; j < rqst[i].rq_nvec; j++) {
			struct kvec *iov = &rqst[i].rq_iov[j];

			addr = (unsigned long)iov->iov_base + skip;
			len = iov->iov_len - skip;
			sg = cifs_sg_set_buf(sg, (void *)addr, len);

			/* See the above comment on the 'skip' assignment */
			skip = 0;
		}
		for (j = 0; j < rqst[i].rq_npages; j++) {
			(*klpe_rqst_page_get_length)(&rqst[i], j, &len, &off);
			sg_set_page(sg++, rqst[i].rq_pages[j], len, off);
		}
	}
	cifs_sg_set_buf(sg, sig, SMB2_SIGNATURE_SIZE);

	return p;
}

static int
klpr_smb2_get_enc_key(struct TCP_Server_Info *server, __u64 ses_id, int enc, u8 *key)
{
	struct cifs_ses *ses;
	u8 *ses_enc_key;

	spin_lock(&(*klpe_cifs_tcp_ses_lock));
	list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
		if (ses->Suid != ses_id)
			continue;
		spin_lock(&ses->ses_lock);
		ses_enc_key = enc ? ses->smb3encryptionkey :
							ses->smb3decryptionkey;
		memcpy(key, ses_enc_key, SMB3_SIGN_KEY_SIZE);
		spin_unlock(&ses->ses_lock);
		spin_unlock(&(*klpe_cifs_tcp_ses_lock));
		return 0;
	}
	spin_unlock(&(*klpe_cifs_tcp_ses_lock));

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
	u8 key[SMB3_SIGN_KEY_SIZE];
	struct aead_request *req;
	u8 *iv;
	DECLARE_CRYPTO_WAIT(wait);
	unsigned int crypt_len = le32_to_cpu(tr_hdr->OriginalMessageSize);
	void *creq;

	rc = klpr_smb2_get_enc_key(server, tr_hdr->SessionId, enc, key);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not get %scryption key\n", __func__,
			 enc ? "en" : "de");
		return rc;
	}

	rc = crypto_aead_setkey(tfm, key, SMB3_SIGN_KEY_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set aead key %d\n", __func__, rc);
		return rc;
	}

	rc = crypto_aead_setauthsize(tfm, SMB2_SIGNATURE_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set authsize %d\n", __func__, rc);
		return rc;
	}

	creq = klpr_smb2_get_aead_req(tfm, rqst, num_rqst, sign, &iv, &req, &sg);
	if (unlikely(!creq))
		return -ENOMEM;

	if (!enc) {
		memcpy(sign, &tr_hdr->Signature, SMB2_SIGNATURE_SIZE);
		crypt_len += SMB2_SIGNATURE_SIZE;
	}

	if (server->cipher_type == SMB2_ENCRYPTION_AES128_GCM)
		memcpy(iv, (char *)tr_hdr->Nonce, SMB3_AES128GCM_NONCE);
	else {
		iv[0] = 3;
		memcpy(iv + 1, (char *)tr_hdr->Nonce, SMB3_AES128CCM_NONCE);
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

	kfree(creq);
	return rc;
}


#include "livepatch_bsc1247240.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "cifs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "cifs_tcp_ses_lock", (void *)&klpe_cifs_tcp_ses_lock, "cifs" },
	{ "rqst_page_get_length", (void *)&klpe_rqst_page_get_length, "cifs" },
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

int livepatch_bsc1247240_init(void)
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

void livepatch_bsc1247240_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
