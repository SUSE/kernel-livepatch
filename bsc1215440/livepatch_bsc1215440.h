#ifndef _LIVEPATCH_BSC1215440_H
#define _LIVEPATCH_BSC1215440_H

#if IS_ENABLED(CONFIG_NET_SCH_HFSC)

struct Qdisc;
struct nlattr;
struct netlink_ext_ack;

int
klpp_hfsc_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
		  struct nlattr **tca, unsigned long *arg,
		  struct netlink_ext_ack *extack);

int livepatch_bsc1215440_init(void);
void livepatch_bsc1215440_cleanup(void);

#else /* !IS_ENABLED(CONFIG_NET_SCH_HFSC) */

static inline int livepatch_bsc1215440_init(void) { return 0; }
static inline void livepatch_bsc1215440_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_NET_SCH_HFSC) */

#endif /* _LIVEPATCH_BSC1215440_H */
