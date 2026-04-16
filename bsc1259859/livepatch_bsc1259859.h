#ifndef _LIVEPATCH_BSC1259859_H
#define _LIVEPATCH_BSC1259859_H

#include <linux/types.h>

int livepatch_bsc1259859_init(void);
static inline void livepatch_bsc1259859_cleanup(void) {}

int bsc1259859_security_apparmor_policy_unpack_init(void);
static inline void bsc1259859_security_apparmor_policy_unpack_cleanup(void) {}

int bsc1259859_security_apparmor_policy_init(void);
static inline void bsc1259859_security_apparmor_policy_cleanup(void) {}

int bsc1259859_security_apparmor_policy_ns_init(void);
static inline void bsc1259859_security_apparmor_policy_ns_cleanup(void) {}

int bsc1259859_security_apparmor_apparmorfs_init(void);
static inline void bsc1259859_security_apparmor_apparmorfs_cleanup(void) {}


struct aa_ext;
struct aa_loaddata;
struct aa_ns;
struct aa_profile;
struct cred;
struct dentry;
struct file;
struct list_head;

int klpp_aa_may_manage_policy(struct aa_profile *profile, struct aa_ns *ns, const struct cred *ocred, const char *op);
int klpp_aa_unpack(struct aa_loaddata *udata, struct list_head *lh, const char **ns);
ssize_t klpp_aa_replace_profiles(struct aa_ns *view, struct aa_profile *profile, bool noreplace, struct aa_loaddata *udata);
ssize_t klpp_profile_load(struct file *f, const char __user *buf, size_t size, loff_t *pos);
ssize_t klpp_profile_remove(struct file *f, const char __user *buf, size_t size, loff_t *pos);
ssize_t klpp_profile_replace(struct file *f, const char __user *buf, size_t size, loff_t *pos);
struct aa_ns *klpp___aa_find_or_create_ns(struct aa_ns *parent, const char *name, struct dentry *dir);
struct aa_ns *klpp_aa_prepare_ns(struct aa_ns *root, const char *name);
struct aa_profile *klpp_unpack_profile(struct aa_ext *e, char **ns_name);
void klpp___remove_profile(struct aa_profile *profile);
#endif /* _LIVEPATCH_BSC1259859_H */
