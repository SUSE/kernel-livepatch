#ifndef _LIVEPATCH_BSC1229273_H
#define _LIVEPATCH_BSC1229273_H

static inline int livepatch_bsc1229273_init(void) { return 0; }
static inline void livepatch_bsc1229273_cleanup(void) {}

struct extent_buffer;

int klpp_check_leaf(struct extent_buffer *leaf, bool check_item_data);

int klpp_btrfs_check_node(struct extent_buffer *node);

#endif /* _LIVEPATCH_BSC1229273_H */
