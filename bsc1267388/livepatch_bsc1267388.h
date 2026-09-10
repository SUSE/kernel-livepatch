#ifndef _LIVEPATCH_BSC1267388_H
#define _LIVEPATCH_BSC1267388_H

#include <linux/types.h>

int livepatch_bsc1267388_init(void);
static inline void livepatch_bsc1267388_cleanup(void) {}

int bsc1267388_fs_notify_fsnotify_init(void);
static inline void bsc1267388_fs_notify_fsnotify_cleanup(void) {}

int bsc1267388_fs_notify_mark_init(void);
static inline void bsc1267388_fs_notify_mark_cleanup(void) {}


struct fsnotify_iter_info;
struct inode;

bool klpp_fsnotify_prepare_user_wait(struct fsnotify_iter_info *iter_info);
int klpp_fsnotify(struct inode *to_tell, __u32 mask, const void *data, int data_is, const unsigned char *name, u32 cookie);

struct fsnotify_mark;

struct fsnotify_mark *klpr_fsnotify_next_mark(struct fsnotify_mark *mark);
#endif /* _LIVEPATCH_BSC1267388_H */
