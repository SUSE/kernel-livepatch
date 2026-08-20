#ifndef _LIVEPATCH_BSC1262213_H
#define _LIVEPATCH_BSC1262213_H

#include <linux/types.h>

static inline int livepatch_bsc1262213_init(void) { return 0; }
static inline void livepatch_bsc1262213_cleanup(void) {}

struct Qdisc;

void klpp_teql_destroy(struct Qdisc *sch);

#endif /* _LIVEPATCH_BSC1262213_H */
