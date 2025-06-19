#ifndef _LIVEPATCH_BSC1233680_H
#define _LIVEPATCH_BSC1233680_H

struct key;;
struct keyring_search_context;

int livepatch_bsc1233680_init(void);
static inline void livepatch_bsc1233680_cleanup(void) {}
bool klpp_search_nested_keyrings(struct key *keyring,
				 struct keyring_search_context *ctx);

#endif /* _LIVEPATCH_BSC1233680_H */
