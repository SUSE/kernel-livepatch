/* klp-ccp: from fs/nfsd/nfs4proc.c */
#define KLPR_NFSDDBG_FACILITY  NFSDDBG_PROC

#undef klpr_ifdebug
# define klpr_ifdebug(fac) if (unlikely((*klpe_nfsd_debug) & KLPR_NFSDDBG_##fac))

# define klpr_dfprintk(fac, fmt, ...)          \
do {                           \
	klpr_ifdebug(fac)               \
	printk(KERN_DEFAULT fmt, ##__VA_ARGS__);    \
} while (0)

#define klpr_dprintk(fmt, ...) \
	klpr_dfprintk(FACILITY, fmt, ##__VA_ARGS__)
