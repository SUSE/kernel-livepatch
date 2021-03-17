#ifndef _LIVEPATCH_BSC1183491_H
#define _LIVEPATCH_BSC1183491_H

#include <linux/types.h>

int livepatch_bsc1183491_scsi_transport_iscsi_init(void);
void livepatch_bsc1183491_scsi_transport_iscsi_cleanup(void);

static inline int livepatch_bsc1183491_libiscsi_init(void) { return 0; }
static inline void livepatch_bsc1183491_libiscsi_cleanup(void) {}

int livepatch_bsc1183491_init(void);
void livepatch_bsc1183491_cleanup(void);


struct device;
struct device_attribute;
struct sk_buff;
struct nlmsghdr;
struct iscsi_cls_session;
enum iscsi_param;
struct sockaddr_storage;
struct iscsi_cls_conn;
struct Scsi_Host;
enum iscsi_host_param;

ssize_t
klpp_show_transport_handle(struct device *dev, struct device_attribute *attr,
		      char *buf);

ssize_t klpp_show_transport_caps(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t
klpp_show_ep_handle(struct device *dev, struct device_attribute *attr, char *buf);

int
klpp_iscsi_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh, uint32_t *group);

ssize_t
klpp_show_priv_session_state(struct device *dev, struct device_attribute *attr,
			char *buf);

ssize_t
klpp_show_priv_session_creator(struct device *dev, struct device_attribute *attr,
			char *buf);

ssize_t
klpp_show_priv_session_target_id(struct device *dev, struct device_attribute *attr,
			    char *buf);

ssize_t klpp_show_priv_session_recovery_tmo(struct device *dev, struct device_attribute *attr, char *buf);

int klpp_iscsi_session_get_param(struct iscsi_cls_session *cls_session,
				   enum iscsi_param param, char *buf);

int klpp_iscsi_conn_get_addr_param(struct sockaddr_storage *addr,
				     enum iscsi_param param, char *buf);

int klpp_iscsi_conn_get_param(struct iscsi_cls_conn *cls_conn,
				enum iscsi_param param, char *buf);

int klpp_iscsi_host_get_param(struct Scsi_Host *shost,
				enum iscsi_host_param param, char *buf);

#endif /* _LIVEPATCH_BSC1183491_H */
