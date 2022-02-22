#ifndef _LIVEPATCH_BSC1194463_H
#define _LIVEPATCH_BSC1194463_H

int livepatch_bsc1194463_init(void);
static inline void livepatch_bsc1194463_cleanup(void) {}

struct socket;
struct msghdr;
struct unix_stream_read_state;

int klpp_unix_dgram_recvmsg(struct socket *sock, struct msghdr *msg,
			      size_t size, int flags);
int klpp_unix_stream_read_generic(struct unix_stream_read_state *state,
				    bool freezable);

#endif /* _LIVEPATCH_BSC1194463_H */
