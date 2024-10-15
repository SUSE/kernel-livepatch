#ifndef _LIVEPATCH_BSC1229273_H
#define _LIVEPATCH_BSC1229273_H

int livepatch_bsc1229273_init(void);
void livepatch_bsc1229273_cleanup(void);

struct extent_buffer;

int klpp_check_leaf(struct extent_buffer *leaf, bool check_item_data);

struct btrfs_info;

int klpp_btrfs_check_node(struct btrfs_fs_info *fs_info, struct extent_buffer *node);

#endif /* _LIVEPATCH_BSC1229273_H */
