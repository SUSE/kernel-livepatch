#ifndef _LIVEPATCH_BSC1223681_H
#define _LIVEPATCH_BSC1223681_H

#if IS_ENABLED(CONFIG_SCSI_QLA_FC)

int livepatch_bsc1223681_init(void);
void livepatch_bsc1223681_cleanup(void);

struct qla_hw_data;
struct req_que;
struct rsp_que;

#include <linux/types.h>

int
klpp_qla2x00_mem_alloc(struct qla_hw_data *ha, uint16_t req_len, uint16_t rsp_len,
	struct req_que **req, struct rsp_que **rsp);

#else /* !IS_ENABLED(CONFIG_SCSI_QLA_FC) */

static inline int livepatch_bsc1223681_init(void) { return 0; }
static inline void livepatch_bsc1223681_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SCSI_QLA_FC) */

#endif /* _LIVEPATCH_BSC1223681_H */
