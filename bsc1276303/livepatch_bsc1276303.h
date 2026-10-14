#ifndef _LIVEPATCH_BSC1276303_H
#define _LIVEPATCH_BSC1276303_H

#include <linux/types.h>

int livepatch_bsc1276303_init(void);
void livepatch_bsc1276303_cleanup(void);


struct ceph_osdmap;

int klpp_decode_new_up_state_weight(void **p, void *end, u8 struct_v, struct ceph_osdmap *map);
#endif /* _LIVEPATCH_BSC1276303_H */
