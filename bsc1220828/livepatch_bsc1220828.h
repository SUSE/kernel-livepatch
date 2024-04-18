#ifndef _LIVEPATCH_BSC1220828_H
#define _LIVEPATCH_BSC1220828_H

#if IS_ENABLED(CONFIG_SECURITY_TOMOYO)

int livepatch_bsc1220828_init(void);
static inline void livepatch_bsc1220828_cleanup(void) {}

struct tomoyo_io_buffer;

ssize_t klpp_tomoyo_write_control(struct tomoyo_io_buffer *head,
			     const char __user *buffer, const int buffer_len);

#else /* !IS_ENABLED(CONFIG_SECURITY_TOMOYO) */

static inline int livepatch_bsc1220828_init(void) { return 0; }
static inline void livepatch_bsc1220828_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SECURITY_TOMOYO) */

#endif /* _LIVEPATCH_BSC1220828_H */
