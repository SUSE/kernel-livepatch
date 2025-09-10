#ifndef _LIVEPATCH_BSC1245685_H
#define _LIVEPATCH_BSC1245685_H

struct mlx5_eswitch;

static inline int livepatch_bsc1245685_init(void) { return 0; }
static inline void livepatch_bsc1245685_cleanup(void) {}
void klpp_mlx5_eswitch_disable_pf_vf_vports(struct mlx5_eswitch *esw);
int klpp_mlx5_eswitch_enable_pf_vf_vports(struct mlx5_eswitch *esw,
					  enum mlx5_eswitch_vport_event enabled_events);

#endif /* _LIVEPATCH_BSC1245685_H */
