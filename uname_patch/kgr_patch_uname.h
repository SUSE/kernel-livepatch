#ifndef _KGR_PATCH_UNAME_H
#define _KGR_PATCH_UNAME_H

#include <linux/utsname.h>

extern int kgr_patch_uname_init(void);
extern asmlinkage long kgr_sys_newuname(struct new_utsname __user *name);

#endif
