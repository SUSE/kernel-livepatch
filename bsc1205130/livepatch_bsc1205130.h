#ifndef _LIVEPATCH_BSC1205130_H
#define _LIVEPATCH_BSC1205130_H

#include <linux/types.h>

struct svc_rqst;
struct nfsd_readdirargs;
struct nfsd_readdirres;
__be32
klpp_nfsd_proc_readdir(struct svc_rqst *rqstp, struct nfsd_readdirargs *argp,
					  struct nfsd_readdirres  *resp);

struct nfsd_readargs;
int klpp_nfssvc_decode_readargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_readargs *args);

struct nfsd3_readargs;
struct nfsd3_readres;
__be32 klpp_nfsd3_proc_read(struct svc_rqst *rqstp, struct nfsd3_readargs *argp,
				        struct nfsd3_readres  *resp);

struct nfsd3_readdirargs;
struct nfsd3_readdirres;
__be32
klpp_nfsd3_proc_readdir(struct svc_rqst *rqstp, struct nfsd3_readdirargs *argp,
					   struct nfsd3_readdirres  *resp);
__be32
klpp_nfsd3_proc_readdirplus(struct svc_rqst *rqstp, struct nfsd3_readdirargs *argp,
					       struct nfsd3_readdirres  *resp);

struct nfsd3_readargs;
int klpp_nfs3svc_decode_readargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readargs *args);

struct nfsd4_compoundargs;
struct nfsd4_compoundres;
__be32
klpp_nfsd4_proc_compound(struct svc_rqst *rqstp, struct nfsd4_compoundargs *args,
		    struct nfsd4_compoundres *resp);

struct nfsd4_op;
int klpp_nfsd4_max_reply(struct svc_rqst *rqstp, struct nfsd4_op *op);

int bsc1205130_fs_nfsd_nfs3proc_init(void);
void bsc1205130_fs_nfsd_nfs3proc_cleanup(void);

int bsc1205130_fs_nfsd_nfs3xdr_init(void);
void bsc1205130_fs_nfsd_nfs3xdr_cleanup(void);

int bsc1205130_fs_nfsd_nfs4proc_init(void);
void bsc1205130_fs_nfsd_nfs4proc_cleanup(void);

int bsc1205130_fs_nfsd_nfsproc_init(void);
void bsc1205130_fs_nfsd_nfsproc_cleanup(void);

int bsc1205130_fs_nfsd_nfsxdr_init(void);
void bsc1205130_fs_nfsd_nfsxdr_cleanup(void);

int livepatch_bsc1205130_init(void);
void livepatch_bsc1205130_cleanup(void);

#endif /* _LIVEPATCH_BSC1205130_H */
