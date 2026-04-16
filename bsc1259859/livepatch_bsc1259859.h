#ifndef _LIVEPATCH_BSC1259859_H
#define _LIVEPATCH_BSC1259859_H

#include <linux/types.h>

static inline int livepatch_bsc1259859_init(void) { return 0; }
static inline void livepatch_bsc1259859_cleanup(void) {}

struct aa_dfa;
struct aa_ext;
struct aa_label;
struct aa_loaddata;
struct aa_ns;
struct aa_policydb;
struct aa_profile;
struct cred;
struct dentry;
struct file;
struct inode;
struct list_head;
struct mnt_idmap;

#define aa_state_t unsigned int

aa_state_t klpp_aa_dfa_match(struct aa_dfa *dfa, aa_state_t start, const char *str);
aa_state_t klpp_aa_dfa_match_len(struct aa_dfa *dfa, aa_state_t start, const char *str, int len);
int klpp_aa_may_manage_policy(struct aa_label *label, struct aa_ns *ns, const struct cred *ocred, u32 mask);
int klpp_aa_unpack(struct aa_loaddata *udata, struct list_head *lh, const char **ns);
int klpp_ns_mkdir_op(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode);
int klpp_ns_rmdir_op(struct inode *dir, struct dentry *dentry);
int klpp_unpack_pdb(struct aa_ext *e, struct aa_policydb *policy, bool required_dfa, bool required_trans, const char **info);
ssize_t klpp_aa_replace_profiles(struct aa_ns *view, struct aa_label *label, u32 mask, struct aa_loaddata *udata);
ssize_t klpp_profile_load(struct file *f, const char __user *buf, size_t size, loff_t *pos);
ssize_t klpp_profile_remove(struct file *f, const char __user *buf, size_t size, loff_t *pos);
ssize_t klpp_profile_replace(struct file *f, const char __user *buf, size_t size, loff_t *pos);
struct aa_dfa *klpp_aa_dfa_unpack(void *blob, size_t size, int flags);
struct aa_ns *klpp___aa_create_ns(struct aa_ns *parent, const char *name, struct dentry *dir);
void klpp___remove_profile(struct aa_profile *profile);

#endif /* _LIVEPATCH_BSC1259859_H */
