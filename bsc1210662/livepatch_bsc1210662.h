#ifndef _LIVEPATCH_BSC1210662_H
#define _LIVEPATCH_BSC1210662_H

int livepatch_bsc1210662_init(void);
void livepatch_bsc1210662_cleanup(void);

struct Scsi_Host;

int klpp_iscsi_sw_tcp_host_get_param(struct Scsi_Host *shost,
				       enum iscsi_host_param param, char *buf);

struct iscsi_endpoint;

struct iscsi_cls_session *
klpp_iscsi_sw_tcp_session_create(struct iscsi_endpoint *ep, uint16_t cmds_max,
			    uint16_t qdepth, uint32_t initial_cmdsn);

#endif /* _LIVEPATCH_BSC1210662_H */
