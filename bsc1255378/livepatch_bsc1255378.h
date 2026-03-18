#ifndef _LIVEPATCH_BSC1255378_H
#define _LIVEPATCH_BSC1255378_H

#include <linux/types.h>

struct ceph_auth_client;

static inline int livepatch_bsc1255378_init(void) { return 0; }
static inline void livepatch_bsc1255378_cleanup(void) {}

int klpp_ceph_x_handle_reply(struct ceph_auth_client *ac, u64 global_id,
			     void *buf, void *end,
			     u8 *session_key, int *session_key_len,
			     u8 *con_secret, int *con_secret_len);

#endif /* _LIVEPATCH_BSC1255378_H */
