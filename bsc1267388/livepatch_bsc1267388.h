#ifndef _LIVEPATCH_BSC1267388_H
#define _LIVEPATCH_BSC1267388_H

#include <linux/types.h>

static inline int livepatch_bsc1267388_init(void) { return 0; }
static inline void livepatch_bsc1267388_cleanup(void) {}

struct fsnotify_iter_info;
struct inode;
struct qstr;

bool klpp_fsnotify_prepare_user_wait(struct fsnotify_iter_info *iter_info);

struct fsnotify_mark;

struct fsnotify_mark *klpr_fsnotify_next_mark(struct fsnotify_mark *mark);

#endif /* _LIVEPATCH_BSC1267388_H */
