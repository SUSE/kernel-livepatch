#ifndef _LIVEPATCH_BSC1233712_H
#define _LIVEPATCH_BSC1233712_H

#if IS_ENABLED(CONFIG_VIRTIO_VSOCKETS_COMMON)

static inline int livepatch_bsc1233712_init(void) { return 0; }
static inline void livepatch_bsc1233712_cleanup(void) {}

void klpp_virtio_transport_destruct(struct vsock_sock *vsk);

#endif /* IS_ENABLED() */

#endif /* _LIVEPATCH_BSC1233712_H */
