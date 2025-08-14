#ifndef _LIVEPATCH_BSC1247351_H
#define _LIVEPATCH_BSC1247351_H

static inline int livepatch_bsc1247351_init(void) { return 0; }
static inline void livepatch_bsc1247351_cleanup(void) {}

u8 *klpp_hid_alloc_report_buf(struct hid_report *report, gfp_t flags);

#endif /* _LIVEPATCH_BSC1247351_H */
