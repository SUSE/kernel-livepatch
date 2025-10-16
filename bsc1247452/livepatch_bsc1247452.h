#ifndef _LIVEPATCH_BSC1247452_H
#define _LIVEPATCH_BSC1247452_H

struct tls_strparser;

static inline int livepatch_bsc1247452_init(void) { return 0; }
static inline void livepatch_bsc1247452_cleanup(void) {}
void klpp_tls_strp_check_rcv(struct tls_strparser *strp);

#endif /* _LIVEPATCH_BSC1247452_H */
