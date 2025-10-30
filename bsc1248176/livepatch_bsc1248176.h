#ifndef _LIVEPATCH_BSC1248176_H
#define _LIVEPATCH_BSC1248176_H

static inline int livepatch_bsc1248176_init(void) { return 0; }
static inline void livepatch_bsc1248176_cleanup(void) {}

struct xe_lmtt;
struct xe_lmtt_pt *klpp_lmtt_pt_alloc(struct xe_lmtt *lmtt, unsigned int level);
struct xe_lmtt_pt;
void klpp_lmtt_destroy_pt(struct xe_lmtt *lmtt, struct xe_lmtt_pt *pd);
struct drm_device;
void klpp_fini_lmtt(struct drm_device *drm, void *arg);
int klpp_xe_lmtt_prepare_pages(struct xe_lmtt *lmtt, unsigned int vfid, u64 range);
void klpp_lmtt_write_pte(struct xe_lmtt *lmtt, struct xe_lmtt_pt *pt,
			   u64 pte, unsigned int idx);
#endif /* _LIVEPATCH_BSC1248176_H */
