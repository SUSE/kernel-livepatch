/*
 * livepatch_bsc1245685
 *
 * Fix for CVE-2025-38109, bsc#1245685
 *
 *  Upstream commit:
 *  687560d8a9a2 ("net/mlx5: Fix ECVF vports unload on shutdown flow")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  37c7c0c9c74a75780602c907fe1b89bacca413fa
 *
 *  SLE MICRO-6-0 commit:
 *  37c7c0c9c74a75780602c907fe1b89bacca413fa
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/eswitch.c */
#include <linux/etherdevice.h>

/* klp-ccp: from include/linux/debugfs.h */
#define _DEBUGFS_H_

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/eswitch.c */
#include <linux/mlx5/driver.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/fs.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/eswitch.h */
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/atomic.h>
#include <linux/xarray.h>
#include <net/devlink.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/eswitch.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/fs.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/lib/mpfs.h */
#include <linux/if_ether.h>
#include <linux/mlx5/device.h>

#define MLX5_L2_ADDR_HASH_SIZE (BIT(BITS_PER_BYTE))

struct l2addr_node {
	struct hlist_node hlist;
	u8                addr[ETH_ALEN];
};

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/lib/fs_chains.h */
#include <linux/mlx5/fs.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/sf/sf.h */
#include <linux/mlx5/driver.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/lib/sf.h */
#include <linux/mlx5/driver.h>

/* klp-ccp: from include/linux/if_vlan.h */
#define _LINUX_IF_VLAN_H_

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en/tc_ct.h */
#include <linux/mlx5/fs.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en.h */
#include <linux/if_vlan.h>
#include <linux/etherdevice.h>
#include <linux/timecounter.h>
#include <linux/net_tstamp.h>

#include <linux/mlx5/driver.h>

/* klp-ccp: from include/linux/mlx5/qp.h */
#define MLX5_QP_H

/* klp-ccp: from include/linux/mlx5/cq.h */
#define MLX5_CORE_CQ_H

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en.h */
#include <linux/mlx5/vport.h>

#include <linux/mlx5/fs.h>

/* klp-ccp: from include/linux/rhashtable.h */
#define _LINUX_RHASHTABLE_H

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en.h */
#include <linux/dim.h>
#include <linux/bits.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/wq.h */
#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/cq.h>
#include <linux/mlx5/qp.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.h */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/if_link.h>
#include <linux/firmware.h>
#include <linux/mlx5/cq.h>
#include <linux/mlx5/fs.h>
#include <linux/mlx5/driver.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/lib/devcom.h */
#include <linux/mlx5/driver.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.h */
static inline u16 mlx5_core_ec_vf_vport_base(const struct mlx5_core_dev *dev)
{
	return MLX5_CAP_GEN_2(dev, ec_vf_vport_base);
}

static inline u16 mlx5_core_ec_sriov_enabled(const struct mlx5_core_dev *dev)
{
	return mlx5_core_is_ecpf(dev) && mlx5_core_ec_vf_vport_base(dev);
}

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en/mod_hdr.h */
#include <linux/hashtable.h>
#include <linux/mlx5/fs.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/lib/fs_ttc.h */
#include <linux/mlx5/fs.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en/qos.h */
#include <linux/mlx5/driver.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/lib/hv.h */
#if IS_ENABLED(CONFIG_PCI_HYPERV_INTERFACE)

#include <linux/mlx5/driver.h>

#endif

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en/rx_res.h */
#include <linux/kernel.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en/rqt.h */
#include <linux/kernel.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en/tir.h */
#include <linux/kernel.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en/selq.h */
#include <linux/kernel.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/eswitch.h */
#ifdef CONFIG_MLX5_ESWITCH

enum mlx5_eswitch_vport_event {
	MLX5_VPORT_UC_ADDR_CHANGE = BIT(0),
	MLX5_VPORT_MC_ADDR_CHANGE = BIT(1),
	MLX5_VPORT_PROMISC_CHANGE = BIT(3),
};

struct mlx5_eswitch_fdb {
	union {
		struct legacy_fdb {
			struct mlx5_flow_table *fdb;
			struct mlx5_flow_group *addr_grp;
			struct mlx5_flow_group *allmulti_grp;
			struct mlx5_flow_group *promisc_grp;
			struct mlx5_flow_table *vepa_fdb;
			struct mlx5_flow_handle *vepa_uplink_rule;
			struct mlx5_flow_handle *vepa_star_rule;
		} legacy;

		struct offloads_fdb {
			struct mlx5_flow_namespace *ns;
			struct mlx5_flow_table *tc_miss_table;
			struct mlx5_flow_table *slow_fdb;
			struct mlx5_flow_group *send_to_vport_grp;
			struct mlx5_flow_group *send_to_vport_meta_grp;
			struct mlx5_flow_group *peer_miss_grp;
			struct mlx5_flow_handle **peer_miss_rules[MLX5_MAX_PORTS];
			struct mlx5_flow_group *miss_grp;
			struct mlx5_flow_handle **send_to_vport_meta_rules;
			struct mlx5_flow_handle *miss_rule_uni;
			struct mlx5_flow_handle *miss_rule_multi;

			struct mlx5_fs_chains *esw_chains_priv;
			struct {
				DECLARE_HASHTABLE(table, 8);
				/* Protects vports.table */
				struct mutex lock;
			} vports;

			struct mlx5_esw_indir_table *indir;

		} offloads;
	};
	u32 flags;
};

struct mlx5_esw_offload {
	struct mlx5_flow_table *ft_offloads_restore;
	struct mlx5_flow_group *restore_group;
	struct mlx5_modify_hdr *restore_copy_hdr_id;
	struct mapping_ctx *reg_c0_obj_pool;

	struct mlx5_flow_table *ft_offloads;
	struct mlx5_flow_group *vport_rx_group;
	struct mlx5_flow_group *vport_rx_drop_group;
	struct mlx5_flow_handle *vport_rx_drop_rule;
	struct mlx5_flow_table *ft_ipsec_tx_pol;
	struct xarray vport_reps;
	struct list_head peer_flows[MLX5_MAX_PORTS];
	struct mutex peer_mutex;
	struct mutex encap_tbl_lock; /* protects encap_tbl */
	DECLARE_HASHTABLE(encap_tbl, 8);
	struct mutex decap_tbl_lock; /* protects decap_tbl */
	DECLARE_HASHTABLE(decap_tbl, 8);
	struct mod_hdr_tbl mod_hdr;
	DECLARE_HASHTABLE(termtbl_tbl, 8);
	struct mutex termtbl_mutex; /* protects termtbl hash */
	struct xarray vhca_map;
	const struct mlx5_eswitch_rep_ops *rep_ops[NUM_REP_TYPES];
	u8 inline_mode;
	atomic64_t num_flows;
	u64 num_block_encap;
	u64 num_block_mode;
	enum devlink_eswitch_encap_mode encap;
	struct ida vport_metadata_ida;
	unsigned int host_number; /* ECPF supports one external host */
};

struct esw_mc_addr { /* SRIOV only */
	struct l2addr_node     node;
	struct mlx5_flow_handle *uplink_rule; /* Forward to uplink rule */
	u32                    refcnt;
};

struct mlx5_esw_functions {
	struct mlx5_nb		nb;
	u16			num_vfs;
	u16			num_ec_vfs;
};

struct mlx5_eswitch {
	struct mlx5_core_dev    *dev;
	struct mlx5_nb          nb;
	struct mlx5_eswitch_fdb fdb_table;
	/* legacy data structures */
	struct hlist_head       mc_table[MLX5_L2_ADDR_HASH_SIZE];
	struct esw_mc_addr mc_promisc;
	/* end of legacy */
	struct dentry *debugfs_root;
	struct workqueue_struct *work_queue;
	struct xarray vports;
	u32 flags;
	int                     total_vports;
	int                     enabled_vports;
	/* Synchronize between vport change events
	 * and async SRIOV admin state changes
	 */
	struct mutex            state_lock;

	/* Protects eswitch mode change that occurs via one or more
	 * user commands, i.e. sriov state change, devlink commands.
	 */
	struct rw_semaphore mode_lock;
	atomic64_t user_count;

	/* Protected with the E-Switch qos domain lock. */
	struct {
		/* Initially 0, meaning no QoS users and QoS is disabled. */
		refcount_t refcnt;
		u32 root_tsar_ix;
		struct mlx5_qos_domain *domain;
		/* Contains all vports with QoS enabled but no explicit node.
		 * Cannot be NULL if QoS is enabled, but may be a fake node
		 * referencing the root TSAR if the esw doesn't support nodes.
		 */
		struct mlx5_esw_sched_node *node0;
	} qos;

	struct mlx5_esw_bridge_offloads *br_offloads;
	struct mlx5_esw_offload offloads;
	int                     mode;
	u16                     manager_vport;
	u16                     first_host_vport;
	u8			num_peers;
	struct mlx5_esw_functions esw_funcs;
	struct {
		u32             large_group_num;
	}  params;
	struct blocking_notifier_head n_head;
	struct xarray paired;
	struct mlx5_devcom_comp_dev *devcom;
	u16 enabled_ipsec_vf_count;
	bool eswitch_operation_in_progress;
};


int mlx5_eswitch_load_vf_vports(struct mlx5_eswitch *esw, u16 num_vfs,
				enum mlx5_eswitch_vport_event enabled_events);
void mlx5_eswitch_unload_vf_vports(struct mlx5_eswitch *esw, u16 num_vfs);

#else  /* CONFIG_MLX5_ESWITCH */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_MLX5_ESWITCH */

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/lib/eq.h */
#include <linux/mlx5/driver.h>
#include <linux/mlx5/eq.h>
#include <linux/mlx5/cq.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/lag/lag.h */
#include <linux/debugfs.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/fs_core.h */
#include <linux/refcount.h>
#include <linux/mlx5/fs.h>
#include <linux/rhashtable.h>
#include <linux/llist.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/devlink.h */
#include <net/devlink.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/ecpf.h */
#include <linux/mlx5/driver.h>

#ifdef CONFIG_MLX5_ESWITCH

int mlx5_cmd_host_pf_enable_hca(struct mlx5_core_dev *dev);
int mlx5_cmd_host_pf_disable_hca(struct mlx5_core_dev *dev);

#else  /* CONFIG_MLX5_ESWITCH */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_MLX5_ESWITCH */

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/en_accel/ipsec.h */
#include <linux/mlx5/device.h>

#include <linux/idr.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/lib/aso.h */
#include <linux/mlx5/qp.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlx5/core/eswitch.c */
extern int mlx5_eswitch_load_pf_vf_vport(struct mlx5_eswitch *esw, u16 vport_num,
					 enum mlx5_eswitch_vport_event enabled_events);

extern void mlx5_eswitch_unload_pf_vf_vport(struct mlx5_eswitch *esw, u16 vport_num);

void mlx5_eswitch_unload_vf_vports(struct mlx5_eswitch *esw, u16 num_vfs);

extern void mlx5_eswitch_unload_ec_vf_vports(struct mlx5_eswitch *esw,
					     u16 num_ec_vfs);

int mlx5_eswitch_load_vf_vports(struct mlx5_eswitch *esw, u16 num_vfs,
				enum mlx5_eswitch_vport_event enabled_events);

extern int mlx5_eswitch_load_ec_vf_vports(struct mlx5_eswitch *esw, u16 num_ec_vfs,
					  enum mlx5_eswitch_vport_event enabled_events);

static int host_pf_enable_hca(struct mlx5_core_dev *dev)
{
	if (!mlx5_core_is_ecpf(dev))
		return 0;

	/* Once vport and representor are ready, take out the external host PF
	 * out of initializing state. Enabling HCA clears the iser->initializing
	 * bit and host PF driver loading can progress.
	 */
	return mlx5_cmd_host_pf_enable_hca(dev);
}

static void host_pf_disable_hca(struct mlx5_core_dev *dev)
{
	if (!mlx5_core_is_ecpf(dev))
		return;

	mlx5_cmd_host_pf_disable_hca(dev);
}

int
klpp_mlx5_eswitch_enable_pf_vf_vports(struct mlx5_eswitch *esw,
				 enum mlx5_eswitch_vport_event enabled_events)
{
	bool pf_needed;
	int ret;

	pf_needed = mlx5_core_is_ecpf_esw_manager(esw->dev) ||
		    esw->mode == MLX5_ESWITCH_LEGACY;

	/* Enable PF vport */
	if (pf_needed) {
		ret = mlx5_eswitch_load_pf_vf_vport(esw, MLX5_VPORT_PF,
						    enabled_events);
		if (ret)
			return ret;
	}

	/* Enable external host PF HCA */
	ret = host_pf_enable_hca(esw->dev);
	if (ret)
		goto pf_hca_err;

	/* Enable ECPF vport */
	if (mlx5_ecpf_vport_exists(esw->dev)) {
		ret = mlx5_eswitch_load_pf_vf_vport(esw, MLX5_VPORT_ECPF, enabled_events);
		if (ret)
			goto ecpf_err;
	}

	/* Enable ECVF vports */
	if (mlx5_core_ec_sriov_enabled(esw->dev)) {
		ret = mlx5_eswitch_load_ec_vf_vports(esw,
						     esw->esw_funcs.num_ec_vfs,
						     enabled_events);
		if (ret)
			goto ec_vf_err;
	}

	/* Enable VF vports */
	ret = mlx5_eswitch_load_vf_vports(esw, esw->esw_funcs.num_vfs,
					  enabled_events);
	if (ret)
		goto vf_err;
	return 0;

vf_err:
	if (mlx5_core_ec_sriov_enabled(esw->dev))
		mlx5_eswitch_unload_ec_vf_vports(esw, esw->esw_funcs.num_ec_vfs);
ec_vf_err:
	if (mlx5_ecpf_vport_exists(esw->dev))
		mlx5_eswitch_unload_pf_vf_vport(esw, MLX5_VPORT_ECPF);
ecpf_err:
	host_pf_disable_hca(esw->dev);
pf_hca_err:
	if (pf_needed)
		mlx5_eswitch_unload_pf_vf_vport(esw, MLX5_VPORT_PF);
	return ret;
}

void klpp_mlx5_eswitch_disable_pf_vf_vports(struct mlx5_eswitch *esw)
{
	mlx5_eswitch_unload_vf_vports(esw, esw->esw_funcs.num_vfs);

	if (mlx5_core_ec_sriov_enabled(esw->dev))
		mlx5_eswitch_unload_ec_vf_vports(esw,
						 esw->esw_funcs.num_ec_vfs);

	if (mlx5_ecpf_vport_exists(esw->dev)) {
		mlx5_eswitch_unload_pf_vf_vport(esw, MLX5_VPORT_ECPF);
	}

	host_pf_disable_hca(esw->dev);

	if (mlx5_core_is_ecpf_esw_manager(esw->dev) ||
	    esw->mode == MLX5_ESWITCH_LEGACY)
		mlx5_eswitch_unload_pf_vf_vport(esw, MLX5_VPORT_PF);
}


#include "livepatch_bsc1245685.h"

#include <linux/livepatch.h>

extern typeof(mlx5_cmd_host_pf_disable_hca) mlx5_cmd_host_pf_disable_hca
	 KLP_RELOC_SYMBOL(mlx5_core, mlx5_core, mlx5_cmd_host_pf_disable_hca);
extern typeof(mlx5_cmd_host_pf_enable_hca) mlx5_cmd_host_pf_enable_hca
	 KLP_RELOC_SYMBOL(mlx5_core, mlx5_core, mlx5_cmd_host_pf_enable_hca);
extern typeof(mlx5_eswitch_load_ec_vf_vports) mlx5_eswitch_load_ec_vf_vports
	 KLP_RELOC_SYMBOL(mlx5_core, mlx5_core, mlx5_eswitch_load_ec_vf_vports);
extern typeof(mlx5_eswitch_load_pf_vf_vport) mlx5_eswitch_load_pf_vf_vport
	 KLP_RELOC_SYMBOL(mlx5_core, mlx5_core, mlx5_eswitch_load_pf_vf_vport);
extern typeof(mlx5_eswitch_load_vf_vports) mlx5_eswitch_load_vf_vports
	 KLP_RELOC_SYMBOL(mlx5_core, mlx5_core, mlx5_eswitch_load_vf_vports);
extern typeof(mlx5_eswitch_unload_ec_vf_vports) mlx5_eswitch_unload_ec_vf_vports
	 KLP_RELOC_SYMBOL(mlx5_core, mlx5_core, mlx5_eswitch_unload_ec_vf_vports);
extern typeof(mlx5_eswitch_unload_pf_vf_vport) mlx5_eswitch_unload_pf_vf_vport
	 KLP_RELOC_SYMBOL(mlx5_core, mlx5_core, mlx5_eswitch_unload_pf_vf_vport);
extern typeof(mlx5_eswitch_unload_vf_vports) mlx5_eswitch_unload_vf_vports
	 KLP_RELOC_SYMBOL(mlx5_core, mlx5_core, mlx5_eswitch_unload_vf_vports);
