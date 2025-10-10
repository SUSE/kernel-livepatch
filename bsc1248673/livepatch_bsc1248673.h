#ifndef _LIVEPATCH_BSC1248673_H
#define _LIVEPATCH_BSC1248673_H

static inline int livepatch_bsc1248673_init(void) { return 0; }
static inline void livepatch_bsc1248673_cleanup(void) {}

struct path;
struct vfsmount *klpp_clone_private_mount(const struct path *path);
#endif /* _LIVEPATCH_BSC1248673_H */
