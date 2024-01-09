#ifndef _LIVEPATCH_BSC1216044_H
#define _LIVEPATCH_BSC1216044_H

int livepatch_bsc1216044_init(void);
void livepatch_bsc1216044_cleanup(void);

struct nvmet_tcp_queue;

void klpp_nvmet_tcp_socket_error(struct nvmet_tcp_queue *queue, int status);

int klpp_nvmet_tcp_handle_icreq(struct nvmet_tcp_queue *queue);

#endif /* _LIVEPATCH_BSC1216044_H */
