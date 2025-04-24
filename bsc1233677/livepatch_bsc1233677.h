#ifndef _LIVEPATCH_BSC1233677_H
#define _LIVEPATCH_BSC1233677_H

static inline int livepatch_bsc1233677_init(void) { return 0; }
static inline void livepatch_bsc1233677_cleanup(void) {}

int klpp_virtnet_probe(struct virtio_device *vdev);

#endif /* _LIVEPATCH_BSC1233677_H */
