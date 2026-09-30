#ifndef _LIVEPATCH_BSC1272283_H
#define _LIVEPATCH_BSC1272283_H

#include <linux/types.h>

static inline int livepatch_bsc1272283_init(void) { return 0; }
static inline void livepatch_bsc1272283_cleanup(void) {}

struct percpu_ref;
struct rcu_head;

void klpp___blkg_release(struct rcu_head *rcu);
void klpp_blkg_release(struct percpu_ref *ref);

#endif /* _LIVEPATCH_BSC1272283_H */
