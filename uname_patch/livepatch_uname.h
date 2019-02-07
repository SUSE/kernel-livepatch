#ifndef _LIVEPATCH_UNAME_H
#define _LIVEPATCH_UNAME_H

#include <linux/utsname.h>

#ifdef USE_KLP_CONVERT
static inline int klp_patch_uname_init(void) { return 0; }
#else
extern int klp_patch_uname_init(void);
#endif

extern asmlinkage long klp_sys_newuname(struct new_utsname __user *name);

#endif
