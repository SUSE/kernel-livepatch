#ifndef _BSC1200608_COMMON_H
#define _BSC1200608_COMMON_H

int livepatch_bsc1200608_sctp_diag_init(void);
void livepatch_bsc1200608_sctp_diag_cleanup(void);

int livepatch_bsc1200608_sctp_endpointola_init(void);
void livepatch_bsc1200608_sctp_endpointola_cleanup(void);

int livepatch_bsc1200608_sctp_socket_init(void);
void livepatch_bsc1200608_sctp_socket_cleanup(void);


struct net;
struct sctp_endpoint;
struct sctp_transport;

int klpp_sctp_endpoint_hold(struct sctp_endpoint *ep);

void klpp_sctp_endpoint_put(struct sctp_endpoint *ep);

typedef int (*sctp_callback_t)(struct sctp_endpoint *, struct sctp_transport *, void *);

int klpp_sctp_transport_traverse_process(sctp_callback_t cb, sctp_callback_t cb_done,
					 struct net *net, int *pos, void *p);

#endif
