#ifndef _LIVEPATCH_BSC1233679_H
#define _LIVEPATCH_BSC1233679_H

static inline int livepatch_bsc1233679_init(void) { return 0; }
static inline void livepatch_bsc1233679_cleanup(void) {}

struct hid_report;

u8 *klpp_hid_alloc_report_buf(struct hid_report *report, gfp_t flags);

#endif /* _LIVEPATCH_BSC1233679_H */
