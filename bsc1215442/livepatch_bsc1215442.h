#ifndef _LIVEPATCH_BSC1215442_H
#define _LIVEPATCH_BSC1215442_H


struct socket;
struct page;

ssize_t klpp_unix_stream_sendpage(struct socket *, struct page *, int offset,
				    size_t size, int flags);

int livepatch_bsc1215442_init(void);
static inline void livepatch_bsc1215442_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1215442_H */
