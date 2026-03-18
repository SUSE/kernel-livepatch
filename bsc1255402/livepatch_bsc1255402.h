#ifndef _LIVEPATCH_BSC1255402_H
#define _LIVEPATCH_BSC1255402_H

struct ceph_client;
struct seq_file;

static inline int livepatch_bsc1255402_init(void) { return 0; }
static inline void livepatch_bsc1255402_cleanup(void) {}

int klpp___ceph_open_session(struct ceph_client *client, unsigned long started);
int klpp_monmap_show(struct seq_file *s, void *p);
int klpp_osdmap_show(struct seq_file *s, void *p);

#endif /* _LIVEPATCH_BSC1255402_H */
