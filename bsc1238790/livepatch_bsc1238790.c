/*
 * livepatch_bsc1238790
 *
 * Fix for CVE-2022-49564, bsc#1238790
 *
 *  Upstream commit:
 *  2acbb8771f6a ("crypto: qat - add param check for DH")
 *
 *  SLE12-SP5 commit:
 *  7f4f28c9e13a6f14d04ca2d7031debbe360a418c
 *
 *  SLE15-SP3 commit:
 *  7e2e7301ab2ac92e4e0ad223ca275f23d1931109
 *
 *  SLE15-SP4 and -SP5 commit:
 *  da607b72ca619f96eb6823869e36419e738940c5
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_CRYPTO_DEV_QAT)

#if !IS_MODULE(CONFIG_CRYPTO_DEV_QAT)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/crypto/qat/qat_common/qat_asym_algs.c */
#include <linux/module.h>
#include <crypto/internal/akcipher.h>
#include <crypto/akcipher.h>
#include <crypto/kpp.h>
#include <crypto/internal/kpp.h>

/* klp-ccp: from include/crypto/dh.h */
#define dh dh_q

/* klp-ccp: from drivers/crypto/qat/qat_common/qat_asym_algs.c */
#include <linux/dma-mapping.h>

#include <crypto/scatterwalk.h>

/* klp-ccp: from drivers/crypto/qat/qat_common/icp_qat_fw.h */
#include <linux/types.h>

#define QAT_FIELD_SET(flags, val, bitpos, mask) \
{ (flags) = (((flags) & (~((mask) << (bitpos)))) | \
		(((val) & (mask)) << (bitpos))) ; }

enum icp_qat_fw_comn_request_id {
	ICP_QAT_FW_COMN_REQ_NULL = 0,
	ICP_QAT_FW_COMN_REQ_CPM_FW_PKE = 3,
	ICP_QAT_FW_COMN_REQ_CPM_FW_LA = 4,
	ICP_QAT_FW_COMN_REQ_CPM_FW_DMA = 7,
	ICP_QAT_FW_COMN_REQ_CPM_FW_COMP = 9,
	ICP_QAT_FW_COMN_REQ_DELIMITER
};

#define ICP_QAT_FW_COMN_REQ_FLAG_SET 1

#define QAT_COMN_PTR_TYPE_BITPOS 0
#define QAT_COMN_PTR_TYPE_MASK 0x1
#define QAT_COMN_CD_FLD_TYPE_BITPOS 1
#define QAT_COMN_CD_FLD_TYPE_MASK 0x1
#define QAT_COMN_PTR_TYPE_FLAT 0x0

#define QAT_COMN_CD_FLD_TYPE_64BIT_ADR 0x0

#define ICP_QAT_FW_COMN_FLAGS_BUILD(cdt, ptr) \
	((((cdt) & QAT_COMN_CD_FLD_TYPE_MASK) << QAT_COMN_CD_FLD_TYPE_BITPOS) \
	 | (((ptr) & QAT_COMN_PTR_TYPE_MASK) << QAT_COMN_PTR_TYPE_BITPOS))

/* klp-ccp: from drivers/crypto/qat/qat_common/icp_qat_fw_pke.h */
struct icp_qat_fw_req_hdr_pke_cd_pars {
	u64 content_desc_addr;
	u32 content_desc_resrvd;
	u32 func_id;
};

struct icp_qat_fw_req_pke_mid {
	u64 opaque;
	u64 src_data_addr;
	u64 dest_data_addr;
};

struct icp_qat_fw_req_pke_hdr {
	u8 resrvd1;
	u8 resrvd2;
	u8 service_type;
	u8 hdr_flags;
	u16 comn_req_flags;
	u16 resrvd4;
	struct icp_qat_fw_req_hdr_pke_cd_pars cd_pars;
};

struct icp_qat_fw_pke_request {
	struct icp_qat_fw_req_pke_hdr pke_hdr;
	struct icp_qat_fw_req_pke_mid pke_mid;
	u8 output_param_count;
	u8 input_param_count;
	u16 resrvd1;
	u32 resrvd2;
	u64 next_req_adr;
};

struct icp_qat_fw_pke_resp;

#define ICP_QAT_FW_PKE_HDR_VALID_FLAG_BITPOS              7
#define ICP_QAT_FW_PKE_HDR_VALID_FLAG_MASK                0x1

#define ICP_QAT_FW_PKE_HDR_VALID_FLAG_SET(hdr_t, val) \
	QAT_FIELD_SET((hdr_t.hdr_flags), (val), \
		ICP_QAT_FW_PKE_HDR_VALID_FLAG_BITPOS, \
		ICP_QAT_FW_PKE_HDR_VALID_FLAG_MASK)

/* klp-ccp: from drivers/crypto/qat/qat_common/adf_accel_devices.h */
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/io.h>
#include <linux/ratelimit.h>

/* klp-ccp: from drivers/crypto/qat/qat_common/adf_cfg_common.h */
#include <linux/types.h>
#include <linux/ioctl.h>

/* klp-ccp: from drivers/crypto/qat/qat_common/adf_accel_devices.h */
#define ADF_PCI_MAX_BARS 3

struct adf_bar {
	resource_size_t base_addr;
	void __iomem *virt_addr;
	resource_size_t size;
} __packed;

struct adf_accel_msix {
	struct msix_entry *entries;
	char **names;
	u32 num_entries;
} __packed;

struct adf_accel_pci {
	struct pci_dev *pci_dev;
	struct adf_accel_msix msix_entries;
	struct adf_bar pci_bars[ADF_PCI_MAX_BARS];
	uint8_t revid;
	uint8_t sku;
} __packed;

struct adf_etr_ring_data;

#define GET_DEV(accel_dev) ((accel_dev)->accel_pci_dev.pci_dev->dev)

struct adf_accel_dev {
	struct adf_etr_data *transport;
	struct adf_hw_device_data *hw_device;
	struct adf_cfg_device_data *cfg;
	struct adf_fw_loader_data *fw_loader;
	struct adf_admin_comms *admin;
	struct list_head crypto_list;
	unsigned long status;
	atomic_t ref_count;
	struct dentry *debugfs_dir;
	struct list_head list;
	struct module *owner;
	struct adf_accel_pci accel_pci_dev;
	union {
		struct {
			/* vf_info is non-zero when SR-IOV is init'ed */
			struct adf_accel_vf_info *vf_info;
		} pf;
		struct {
			char *irq_name;
			struct tasklet_struct pf2vf_bh_tasklet;
			struct mutex vf2pf_lock; /* protect CSR access */
			struct completion iov_msg_completion;
			uint8_t compatible;
			uint8_t pf_version;
		} vf;
	};
	bool is_vf;
	u32 accel_id;
} __packed;

/* klp-ccp: from drivers/crypto/qat/qat_common/adf_transport.h */
static int (*klpe_adf_send_message)(struct adf_etr_ring_data *ring, uint32_t *msg);

/* klp-ccp: from drivers/crypto/qat/qat_common/adf_common_drv.h */
#include <linux/list.h>
#include <linux/pci.h>

/* klp-ccp: from drivers/crypto/qat/qat_common/qat_crypto.h */
#include <linux/list.h>
#include <linux/slab.h>

struct qat_crypto_instance {
	struct adf_etr_ring_data *sym_tx;
	struct adf_etr_ring_data *sym_rx;
	struct adf_etr_ring_data *pke_tx;
	struct adf_etr_ring_data *pke_rx;
	struct adf_accel_dev *accel_dev;
	struct list_head list;
	unsigned long state;
	int id;
	atomic_t refctr;
};

/* klp-ccp: from drivers/crypto/qat/qat_common/qat_asym_algs.c */
struct qat_rsa_input_params {
	union {
		struct {
			dma_addr_t m;
			dma_addr_t e;
			dma_addr_t n;
		} enc;
		struct {
			dma_addr_t c;
			dma_addr_t d;
			dma_addr_t n;
		} dec;
		struct {
			dma_addr_t c;
			dma_addr_t p;
			dma_addr_t q;
			dma_addr_t dp;
			dma_addr_t dq;
			dma_addr_t qinv;
		} dec_crt;
		u64 in_tab[8];
	};
} __packed __aligned(64);

struct qat_rsa_output_params {
	union {
		struct {
			dma_addr_t c;
		} enc;
		struct {
			dma_addr_t m;
		} dec;
		u64 out_tab[8];
	};
} __packed __aligned(64);

struct qat_dh_input_params {
	union {
		struct {
			dma_addr_t b;
			dma_addr_t xa;
			dma_addr_t p;
		} in;
		struct {
			dma_addr_t xa;
			dma_addr_t p;
		} in_g2;
		u64 in_tab[8];
	};
} __packed __aligned(64);

struct qat_dh_output_params {
	union {
		dma_addr_t r;
		u64 out_tab[8];
	};
} __packed __aligned(64);

struct qat_dh_ctx {
	char *g;
	char *xa;
	char *p;
	dma_addr_t dma_g;
	dma_addr_t dma_xa;
	dma_addr_t dma_p;
	unsigned int p_size;
	bool g2;
	struct qat_crypto_instance *inst;
} __packed __aligned(64);

struct qat_asym_request {
	union {
		struct qat_rsa_input_params rsa;
		struct qat_dh_input_params dh;
	} in;
	union {
		struct qat_rsa_output_params rsa;
		struct qat_dh_output_params dh;
	} out;
	dma_addr_t phy_in;
	dma_addr_t phy_out;
	char *src_align;
	char *dst_align;
	struct icp_qat_fw_pke_request req;
	union {
		struct qat_rsa_ctx *rsa;
		struct qat_dh_ctx *dh;
	} ctx;
	union {
		struct akcipher_request *rsa;
		struct kpp_request *dh;
	} areq;
	int err;
	void (*cb)(struct icp_qat_fw_pke_resp *resp);
} __aligned(64);

static void (*klpe_qat_dh_cb)(struct icp_qat_fw_pke_resp *resp);

#define PKE_DH_1536 0x390c1a49
#define PKE_DH_G2_1536 0x2e0b1a3e
#define PKE_DH_2048 0x4d0c1a60
#define PKE_DH_G2_2048 0x3e0b1a55
#define PKE_DH_3072 0x510c1a77
#define PKE_DH_G2_3072 0x3a0b1a6c
#define PKE_DH_4096 0x690c1a8e
#define PKE_DH_G2_4096 0x4a0b1a83

static unsigned long qat_dh_fn_id(unsigned int len, bool g2)
{
	unsigned int bitslen = len << 3;

	switch (bitslen) {
	case 1536:
		return g2 ? PKE_DH_G2_1536 : PKE_DH_1536;
	case 2048:
		return g2 ? PKE_DH_G2_2048 : PKE_DH_2048;
	case 3072:
		return g2 ? PKE_DH_G2_3072 : PKE_DH_3072;
	case 4096:
		return g2 ? PKE_DH_G2_4096 : PKE_DH_4096;
	default:
		return 0;
	};
}

int klpp_qat_dh_compute_value(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct qat_dh_ctx *ctx = kpp_tfm_ctx(tfm);
	struct qat_crypto_instance *inst = ctx->inst;
	struct device *dev = &GET_DEV(inst->accel_dev);
	struct qat_asym_request *qat_req =
			PTR_ALIGN(kpp_request_ctx(req), 64);
	struct icp_qat_fw_pke_request *msg = &qat_req->req;
	int ret, ctr = 0;
	int n_input_params = 0;
	u8 *vaddr;

	if (unlikely(!ctx->xa))
		return -EINVAL;

	if (req->dst_len < ctx->p_size) {
		req->dst_len = ctx->p_size;
		return -EOVERFLOW;
	}

	if (req->src_len > ctx->p_size)
		return -EINVAL;

	memset(msg, '\0', sizeof(*msg));
	ICP_QAT_FW_PKE_HDR_VALID_FLAG_SET(msg->pke_hdr,
					  ICP_QAT_FW_COMN_REQ_FLAG_SET);

	msg->pke_hdr.cd_pars.func_id = qat_dh_fn_id(ctx->p_size,
						    !req->src && ctx->g2);
	if (unlikely(!msg->pke_hdr.cd_pars.func_id))
		return -EINVAL;

	qat_req->cb = (*klpe_qat_dh_cb);
	qat_req->ctx.dh = ctx;
	qat_req->areq.dh = req;
	msg->pke_hdr.service_type = ICP_QAT_FW_COMN_REQ_CPM_FW_PKE;
	msg->pke_hdr.comn_req_flags =
		ICP_QAT_FW_COMN_FLAGS_BUILD(QAT_COMN_PTR_TYPE_FLAT,
					    QAT_COMN_CD_FLD_TYPE_64BIT_ADR);

	/*
	 * If no source is provided use g as base
	 */
	if (req->src) {
		qat_req->in.dh.in.xa = ctx->dma_xa;
		qat_req->in.dh.in.p = ctx->dma_p;
		n_input_params = 3;
	} else {
		if (ctx->g2) {
			qat_req->in.dh.in_g2.xa = ctx->dma_xa;
			qat_req->in.dh.in_g2.p = ctx->dma_p;
			n_input_params = 2;
		} else {
			qat_req->in.dh.in.b = ctx->dma_g;
			qat_req->in.dh.in.xa = ctx->dma_xa;
			qat_req->in.dh.in.p = ctx->dma_p;
			n_input_params = 3;
		}
	}

	ret = -ENOMEM;
	if (req->src) {
		/*
		 * src can be of any size in valid range, but HW expects it to
		 * be the same as modulo p so in case it is different we need
		 * to allocate a new buf and copy src data.
		 * In other case we just need to map the user provided buffer.
		 * Also need to make sure that it is in contiguous buffer.
		 */
		if (sg_is_last(req->src) && req->src_len == ctx->p_size) {
			qat_req->src_align = NULL;
			vaddr = sg_virt(req->src);
		} else {
			int shift = ctx->p_size - req->src_len;

			qat_req->src_align = kzalloc(ctx->p_size, GFP_KERNEL);
			if (unlikely(!qat_req->src_align))
				return ret;

			scatterwalk_map_and_copy(qat_req->src_align + shift,
						 req->src, 0, req->src_len, 0);

			vaddr = qat_req->src_align;
		}

		qat_req->in.dh.in.b = dma_map_single(dev, vaddr, ctx->p_size,
						     DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(dev, qat_req->in.dh.in.b)))
			goto unmap_src;
	}
	/*
	 * dst can be of any size in valid range, but HW expects it to be the
	 * same as modulo m so in case it is different we need to allocate a
	 * new buf and copy src data.
	 * In other case we just need to map the user provided buffer.
	 * Also need to make sure that it is in contiguous buffer.
	 */
	if (sg_is_last(req->dst) && req->dst_len == ctx->p_size) {
		qat_req->dst_align = NULL;
		vaddr = sg_virt(req->dst);
	} else {
		qat_req->dst_align = kzalloc(ctx->p_size, GFP_KERNEL);
		if (unlikely(!qat_req->dst_align))
			goto unmap_src;

		vaddr = qat_req->dst_align;
	}
	qat_req->out.dh.r = dma_map_single(dev, vaddr, ctx->p_size,
					   DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(dev, qat_req->out.dh.r)))
		goto unmap_dst;

	qat_req->in.dh.in_tab[n_input_params] = 0;
	qat_req->out.dh.out_tab[1] = 0;
	/* Mapping in.in.b or in.in_g2.xa is the same */
	qat_req->phy_in = dma_map_single(dev, &qat_req->in.dh.in.b,
					 sizeof(struct qat_dh_input_params),
					 DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, qat_req->phy_in)))
		goto unmap_dst;

	qat_req->phy_out = dma_map_single(dev, &qat_req->out.dh.r,
					  sizeof(struct qat_dh_output_params),
					  DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, qat_req->phy_out)))
		goto unmap_in_params;

	msg->pke_mid.src_data_addr = qat_req->phy_in;
	msg->pke_mid.dest_data_addr = qat_req->phy_out;
	msg->pke_mid.opaque = (uint64_t)(__force long)qat_req;
	msg->input_param_count = n_input_params;
	msg->output_param_count = 1;

	do {
		ret = (*klpe_adf_send_message)(ctx->inst->pke_tx, (uint32_t *)msg);
	} while (ret == -EBUSY && ctr++ < 100);

	if (!ret)
		return -EINPROGRESS;

	if (!dma_mapping_error(dev, qat_req->phy_out))
		dma_unmap_single(dev, qat_req->phy_out,
				 sizeof(struct qat_dh_output_params),
				 DMA_TO_DEVICE);
unmap_in_params:
	if (!dma_mapping_error(dev, qat_req->phy_in))
		dma_unmap_single(dev, qat_req->phy_in,
				 sizeof(struct qat_dh_input_params),
				 DMA_TO_DEVICE);
unmap_dst:
	if (!dma_mapping_error(dev, qat_req->out.dh.r))
		dma_unmap_single(dev, qat_req->out.dh.r, ctx->p_size,
				 DMA_FROM_DEVICE);
	kzfree(qat_req->dst_align);
unmap_src:
	if (req->src) {
		if (!dma_mapping_error(dev, qat_req->in.dh.in.b))
			dma_unmap_single(dev, qat_req->in.dh.in.b,
					 ctx->p_size,
					 DMA_TO_DEVICE);
		kzfree(qat_req->src_align);
	}
	return ret;
}


#include "livepatch_bsc1238790.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "intel_qat"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "adf_send_message", (void *)&klpe_adf_send_message, "intel_qat" },
	{ "qat_dh_cb", (void *)&klpe_qat_dh_cb, "intel_qat" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1238790_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1238790_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_CRYPTO_DEV_QAT) */
