#ifndef _LIVEPATCH_BSC1247158_H
#define _LIVEPATCH_BSC1247158_H


#include "../klp_syscalls.h"
#include <linux/types.h>

inline int livepatch_bsc1247158_init(void);
inline void livepatch_bsc1247158_cleanup(void);

struct inode;
struct super_block;
struct file_operations;

struct inode *
klpp_anon_inode_make_secure_inode(struct super_block *sb, const char *name,
                                  const struct inode *context_inode);

struct file *klpp___anon_inode_getfile(const char *name,
                                       const struct file_operations *fops,
                                       void *priv, int flags,
                                       const struct inode *context_inode,
                                       bool make_inode);


#if defined(CONFIG_SECRETMEM)

KLP_SYSCALL_DECLx(1, KLP_SYSCALL_SYM(klpp_memfd_secret), unsigned int, flags);

#ifdef KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS
KLP_SYSCALL_DECLx(1, KLP_SYSCALL_COMPAT_STUB_SYM(klpp_memfd_secret),
                  unsigned int, flags);
#endif /* KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS */

#endif /* CONFIG_SECRETMEM */
#endif /* _LIVEPATCH_BSC1247158_H */
