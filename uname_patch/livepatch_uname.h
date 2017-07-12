#ifndef _LIVEPATCH_UNAME_H
#define _LIVEPATCH_UNAME_H

#include <linux/utsname.h>

extern int klp_patch_uname_init(void);
extern asmlinkage long klp_sys_newuname(struct new_utsname __user *name);

#endif
