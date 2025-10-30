#ifndef _LIVEPATCH_BSC1247737_H
#define _LIVEPATCH_BSC1247737_H

struct io_kiocb;
struct io_tw_state;

static inline int livepatch_bsc1247737_init(void) { return 0; }
static inline void livepatch_bsc1247737_cleanup(void) {}
int klpp_io_msg_ring(struct io_kiocb *req, unsigned int issue_flags);
void klpp_io_msg_tw_complete(struct io_kiocb *req, struct io_tw_state *ts);

#endif /* _LIVEPATCH_BSC1247737_H */
