#ifndef _LIVEPATCH_BSC1255402_H
#define _LIVEPATCH_BSC1255402_H

struct ceph_client;
struct seq_file;

int livepatch_bsc1255402_init(void);
void livepatch_bsc1255402_cleanup(void);

int bsc1255402_net_ceph_ceph_common_init(void);
void bsc1255402_net_ceph_ceph_common_cleanup(void);

int bsc1255402_net_ceph_debugfs_init(void);
void bsc1255402_net_ceph_debugfs_cleanup(void);

int klpp___ceph_open_session(struct ceph_client *client,
			     unsigned long started);
int klpp_monmap_show(struct seq_file *s, void *p);
int klpp_osdmap_show(struct seq_file *s, void *p);

#endif /* _LIVEPATCH_BSC1255402_H */
