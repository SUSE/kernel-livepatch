#ifndef _LIVEPATCH_BSC1224991_H
#define _LIVEPATCH_BSC1224991_H

int klpp_unix_stream_read_generic(struct unix_stream_read_state *state,
                                  bool freezable);

static inline int livepatch_bsc1224991_init(void) { return 0; }
static inline void livepatch_bsc1224991_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1224991_H */
