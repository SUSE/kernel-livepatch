#ifndef _LIVEPATCH_BSC1190118_H
#define _LIVEPATCH_BSC1190118_H

int livepatch_bsc1190118_init(void);
static inline void livepatch_bsc1190118_cleanup(void) {}

struct port;
struct work_struct;
struct virtqueue;

void klpp_discard_port_data(struct port *port);
bool klpp_port_has_data(struct port *port);
void klpp_control_work_handler(struct work_struct *work);
void klpp_in_intr(struct virtqueue *vq);

#endif /* _LIVEPATCH_BSC1190118_H */
