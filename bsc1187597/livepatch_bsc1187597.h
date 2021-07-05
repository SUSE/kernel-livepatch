#ifndef _LIVEPATCH_BSC1187597_H
#define _LIVEPATCH_BSC1187597_H

#if IS_ENABLED(CONFIG_HID)

static inline int livepatch_bsc1187597_init(void) { return 0; }
static inline void livepatch_bsc1187597_cleanup(void) {}


struct hid_parser;

int klpp_hid_add_field(struct hid_parser *parser, unsigned report_type, unsigned flags);

#else /* !IS_ENABLED(CONFIG_HID) */

static inline int livepatch_bsc1187597_init(void) { return 0; }

static inline void livepatch_bsc1187597_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_HID) */
#endif /* _LIVEPATCH_BSC1187597_H */
