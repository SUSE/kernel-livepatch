#ifndef _LIVEPATCH_BSC1266265_H
#define _LIVEPATCH_BSC1266265_H

#include <linux/types.h>

static inline int livepatch_bsc1266265_init(void) { return 0; }
static inline void livepatch_bsc1266265_cleanup(void) {}

#include <linux/cred.h>

struct cred;
struct key;
struct key_restriction;
struct key_type;

struct key *klpp_key_alloc(struct key_type *type, const char *desc, kuid_t uid, kgid_t gid, const struct cred *cred, key_perm_t perm, unsigned long flags, struct key_restriction *restrict_link);

void klpp_cifs_spnego_key_destroy(struct key *key);

#endif /* _LIVEPATCH_BSC1266265_H */
