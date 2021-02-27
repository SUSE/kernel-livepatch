/*
 * livepatch_bsc1178684
 *
 * Fix for CVE-2020-28374, bsc#1178684
 *
 *  Upstream commit:
 *  2896c93811e3 ("scsi: target: Fix XCOPY NAA identifier lookup")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  18cb7d2a542812ced4b78470dfe1e798d406fbdd
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  2765e76537212ade12b30b5fe9514be0dd9c51f3
 *
 *  SLE15-SP2 commit:
 *  3e5427c4c89943b08a12348e905c8688fb746f36
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if !IS_MODULE(CONFIG_TARGET_CORE)
#error "Live patch supports only CONFIG_TARGET_CORE=m"
#endif

/* klp-ccp: from drivers/target/target_core_xcopy.c */
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/configfs.h>
#include <linux/ratelimit.h>
#include <scsi/scsi_proto.h>
#include <asm/unaligned.h>
#include <target/target_core_base.h>

/* klp-ccp: from include/target/target_core_backend.h */
static void	(*klpe_target_complete_cmd)(struct se_cmd *, u8);

static void	*(*klpe_transport_kmap_data_sg)(struct se_cmd *);
static void	(*klpe_transport_kunmap_data_sg)(struct se_cmd *);

/* klp-ccp: from drivers/target/target_core_xcopy.c */
#include <target/target_core_fabric.h>

/* klp-ccp: from include/target/target_core_fabric.h */
static void	(*klpe_transport_init_se_cmd)(struct se_cmd *,
		const struct target_core_fabric_ops *,
		struct se_session *, u32, int, int, unsigned char *);

static int	(*klpe_transport_generic_free_cmd)(struct se_cmd *, int);

static int	(*klpe_target_alloc_sgl)(struct scatterlist **sgl, unsigned int *nents,
		u32 length, bool zero_page, bool chainable);
static void	(*klpe_target_free_sgl)(struct scatterlist *sgl, int nents);

/* klp-ccp: from drivers/target/target_core_internal.h */
#include <linux/configfs.h>
#include <linux/list.h>
#include <linux/types.h>
#include <target/target_core_base.h>

static int	(*klpe_target_for_each_device)(int (*fn)(struct se_device *dev, void *data),
			       void *data);

/* klp-ccp: from drivers/target/target_core_pr.h */
#include <linux/types.h>
#include <target/target_core_base.h>

static void (*klpe_spc_parse_naa_6h_vendor_specific)(struct se_device *, unsigned char *);

/* klp-ccp: from drivers/target/target_core_ua.h */
#include <target/target_core_base.h>
/* klp-ccp: from drivers/target/target_core_xcopy.h */
#include <target/target_core_base.h>

#define XCOPY_HDR_LEN			16
#define XCOPY_TARGET_DESC_LEN		32
#define XCOPY_SEGMENT_DESC_LEN		28
#define XCOPY_NAA_IEEE_REGEX_LEN	16
#define XCOPY_MAX_SECTORS		4096

#define XCOPY_CSCD_DESC_ID_LIST_OFF_MAX	0x07FF

enum xcopy_origin_list {
	XCOL_SOURCE_RECV_OP = 0x01,
	XCOL_DEST_RECV_OP = 0x02,
};

struct xcopy_op {
	int op_origin;

	struct se_cmd *xop_se_cmd;
	struct se_device *src_dev;
	unsigned char src_tid_wwn[XCOPY_NAA_IEEE_REGEX_LEN];
	struct se_device *dst_dev;
	unsigned char dst_tid_wwn[XCOPY_NAA_IEEE_REGEX_LEN];
	unsigned char local_dev_wwn[XCOPY_NAA_IEEE_REGEX_LEN];

	sector_t src_lba;
	sector_t dst_lba;
	unsigned short stdi;
	unsigned short dtdi;
	unsigned short nolb;

	u32 xop_data_bytes;
	u32 xop_data_nents;
	struct scatterlist *xop_data_sg;
	struct work_struct xop_work;
};

#define RCR_OP_MAX_TARGET_DESC_COUNT	0x2
#define RCR_OP_MAX_SG_DESC_COUNT	0x1
#define RCR_OP_MAX_DESC_LIST_LEN	1024

/* klp-ccp: from drivers/target/target_core_xcopy.c */
/*
 * Fix CVE-2020-28374
 *  -1 line, +2 lines
 */
static sense_reason_t klpp_target_parse_xcopy_cmd(struct xcopy_op *xop,
					     struct percpu_ref **remote_lun_ref);

static int klpr_target_xcopy_gen_naa_ieee(struct se_device *dev, unsigned char *buf)
{
	int off = 0;

	buf[off++] = (0x6 << 4);
	buf[off++] = 0x01;
	buf[off++] = 0x40;
	buf[off] = (0x5 << 4);

	(*klpe_spc_parse_naa_6h_vendor_specific)(dev, &buf[off]);
	return 0;
}

static int klpp_target_xcopy_locate_se_dev_e4_iter(struct se_device *se_dev,
					      /*
					       * Fix CVE-2020-28374
					       *  -1 line, +1 line
					       */
					      const unsigned char *dev_wwn)
{
	/*
	 * Fix CVE-2020-28374
	 *  -1 line
	 */
	unsigned char tmp_dev_wwn[XCOPY_NAA_IEEE_REGEX_LEN];
	int rc;

	/*
	 * Fix CVE-2020-28374
	 *  -2 lines, +4 lines
	 */
	if (!se_dev->dev_attrib.emulate_3pc) {
		pr_debug("XCOPY: emulate_3pc disabled on se_dev %p\n", se_dev);
		return 0;
	}

	memset(&tmp_dev_wwn[0], 0, XCOPY_NAA_IEEE_REGEX_LEN);
	klpr_target_xcopy_gen_naa_ieee(se_dev, &tmp_dev_wwn[0]);

	/*
	 * Fix CVE-2020-28374
	 *  -1 line, +1 line
	 */
	rc = memcmp(&tmp_dev_wwn[0], dev_wwn, XCOPY_NAA_IEEE_REGEX_LEN);
	/*
	 * Fix CVE-2020-28374
	 *  -2 lines, +6 lines
	 */
	if (rc != 0) {
		pr_debug("XCOPY: skip non-matching: %*ph\n",
			 XCOPY_NAA_IEEE_REGEX_LEN, tmp_dev_wwn);
		return 0;
	}
	pr_debug("XCOPY 0xe4: located se_dev: %p\n", se_dev);

	/*
	 * Fix CVE-2020-28374
	 *  -12 lines
	 */
	return 1;
}

/*
 * Fix CVE-2020-28374
 *  -2 lines, +4 lines
 */
static int klpp_target_xcopy_locate_se_dev_e4(struct se_session *sess,
					const unsigned char *dev_wwn,
					struct se_device **_found_dev,
					struct percpu_ref **_found_lun_ref)
{
	/*
	 * Fix CVE-2020-28374
	 *  -2 lines, +5 lines
	 */
	struct se_dev_entry *deve;
	struct se_node_acl *nacl;
	struct se_lun *this_lun = NULL;
	struct se_device *found_dev = NULL;
	int rc = 0;

	/*
	 * Fix CVE-2020-28374
	 *  -2 lines, +3 lines
	 */
	/* cmd with NULL sess indicates no associated $FABRIC_MOD */
	if (!sess)
		goto err_out;

	/*
	 * Fix CVE-2020-28374
	 *  -8 lines, +30 lines
	 */
	pr_debug("XCOPY 0xe4: searching for: %*ph\n",
		 XCOPY_NAA_IEEE_REGEX_LEN, dev_wwn);

	nacl = sess->se_node_acl;
	rcu_read_lock();
	hlist_for_each_entry_rcu(deve, &nacl->lun_entry_hlist, link) {
		struct se_device *this_dev;

		this_lun = rcu_dereference(deve->se_lun);
		this_dev = rcu_dereference_raw(this_lun->lun_se_dev);

		rc = klpp_target_xcopy_locate_se_dev_e4_iter(this_dev, dev_wwn);
		if (rc) {
			if (percpu_ref_tryget_live(&this_lun->lun_ref))
				found_dev = this_dev;
			break;
		}
	}
	rcu_read_unlock();
	if (found_dev == NULL)
		goto err_out;

	pr_debug("lun_ref held for se_dev: %p se_dev->se_dev_group: %p\n",
		 found_dev, &found_dev->dev_group);
	*_found_dev = found_dev;
	*_found_lun_ref = &this_lun->lun_ref;
	return 0;
err_out:
	pr_debug_ratelimited("Unable to locate 0xe4 descriptor for EXTENDED_COPY\n");
	return -EINVAL;
}

static int target_xcopy_parse_tiddesc_e4(struct se_cmd *se_cmd, struct xcopy_op *xop,
				unsigned char *p, unsigned short cscd_index)
{
	unsigned char *desc = p;
	unsigned short ript;
	u8 desig_len;
	/*
	 * Extract RELATIVE INITIATOR PORT IDENTIFIER
	 */
	ript = get_unaligned_be16(&desc[2]);
	pr_debug("XCOPY 0xe4: RELATIVE INITIATOR PORT IDENTIFIER: %hu\n", ript);
	/*
	 * Check for supported code set, association, and designator type
	 */
	if ((desc[4] & 0x0f) != 0x1) {
		pr_err("XCOPY 0xe4: code set of non binary type not supported\n");
		return -EINVAL;
	}
	if ((desc[5] & 0x30) != 0x00) {
		pr_err("XCOPY 0xe4: association other than LUN not supported\n");
		return -EINVAL;
	}
	if ((desc[5] & 0x0f) != 0x3) {
		pr_err("XCOPY 0xe4: designator type unsupported: 0x%02x\n",
				(desc[5] & 0x0f));
		return -EINVAL;
	}
	/*
	 * Check for matching 16 byte length for NAA IEEE Registered Extended
	 * Assigned designator
	 */
	desig_len = desc[7];
	if (desig_len != XCOPY_NAA_IEEE_REGEX_LEN) {
		pr_err("XCOPY 0xe4: invalid desig_len: %d\n", (int)desig_len);
		return -EINVAL;
	}
	pr_debug("XCOPY 0xe4: desig_len: %d\n", (int)desig_len);
	/*
	 * Check for NAA IEEE Registered Extended Assigned header..
	 */
	if ((desc[8] & 0xf0) != 0x60) {
		pr_err("XCOPY 0xe4: Unsupported DESIGNATOR TYPE: 0x%02x\n",
					(desc[8] & 0xf0));
		return -EINVAL;
	}

	if (cscd_index != xop->stdi && cscd_index != xop->dtdi) {
		pr_debug("XCOPY 0xe4: ignoring CSCD entry %d - neither src nor "
			 "dest\n", cscd_index);
		return 0;
	}

	if (cscd_index == xop->stdi) {
		memcpy(&xop->src_tid_wwn[0], &desc[8], XCOPY_NAA_IEEE_REGEX_LEN);
		/*
		 * Determine if the source designator matches the local device
		 */
		if (!memcmp(&xop->local_dev_wwn[0], &xop->src_tid_wwn[0],
				XCOPY_NAA_IEEE_REGEX_LEN)) {
			xop->op_origin = XCOL_SOURCE_RECV_OP;
			xop->src_dev = se_cmd->se_dev;
			pr_debug("XCOPY 0xe4: Set xop->src_dev %p from source"
					" received xop\n", xop->src_dev);
		}
	}

	if (cscd_index == xop->dtdi) {
		memcpy(&xop->dst_tid_wwn[0], &desc[8], XCOPY_NAA_IEEE_REGEX_LEN);
		/*
		 * Determine if the destination designator matches the local
		 * device. If @cscd_index corresponds to both source (stdi) and
		 * destination (dtdi), or dtdi comes after stdi, then
		 * XCOL_DEST_RECV_OP wins.
		 */
		if (!memcmp(&xop->local_dev_wwn[0], &xop->dst_tid_wwn[0],
				XCOPY_NAA_IEEE_REGEX_LEN)) {
			xop->op_origin = XCOL_DEST_RECV_OP;
			xop->dst_dev = se_cmd->se_dev;
			pr_debug("XCOPY 0xe4: Set xop->dst_dev: %p from destination"
				" received xop\n", xop->dst_dev);
		}
	}

	return 0;
}

static int klpp_target_xcopy_parse_target_descriptors(struct se_cmd *se_cmd,
				struct xcopy_op *xop, unsigned char *p,
				/*
				 * Fix CVE-2020-28374
				 *  -1 line, +2 lines
				 */
				unsigned short tdll, sense_reason_t *sense_ret,
				struct percpu_ref **remote_lun_ref)
{
	struct se_device *local_dev = se_cmd->se_dev;
	unsigned char *desc = p;
	int offset = tdll % XCOPY_TARGET_DESC_LEN, rc;
	unsigned short cscd_index = 0;
	unsigned short start = 0;

	*sense_ret = TCM_INVALID_PARAMETER_LIST;

	if (offset != 0) {
		pr_err("XCOPY target descriptor list length is not"
			" multiple of %d\n", XCOPY_TARGET_DESC_LEN);
		*sense_ret = TCM_UNSUPPORTED_TARGET_DESC_TYPE_CODE;
		return -EINVAL;
	}
	if (tdll > RCR_OP_MAX_TARGET_DESC_COUNT * XCOPY_TARGET_DESC_LEN) {
		pr_err("XCOPY target descriptor supports a maximum"
			" two src/dest descriptors, tdll: %hu too large..\n", tdll);
		/* spc4r37 6.4.3.4 CSCD DESCRIPTOR LIST LENGTH field */
		*sense_ret = TCM_TOO_MANY_TARGET_DESCS;
		return -EINVAL;
	}
	/*
	 * Generate an IEEE Registered Extended designator based upon the
	 * se_device the XCOPY was received upon..
	 */
	memset(&xop->local_dev_wwn[0], 0, XCOPY_NAA_IEEE_REGEX_LEN);
	klpr_target_xcopy_gen_naa_ieee(local_dev, &xop->local_dev_wwn[0]);

	while (start < tdll) {
		/*
		 * Check target descriptor identification with 0xE4 type, and
		 * compare the current index with the CSCD descriptor IDs in
		 * the segment descriptor. Use VPD 0x83 WWPN matching ..
		 */
		switch (desc[0]) {
		case 0xe4:
			rc = target_xcopy_parse_tiddesc_e4(se_cmd, xop,
							&desc[0], cscd_index);
			if (rc != 0)
				goto out;
			start += XCOPY_TARGET_DESC_LEN;
			desc += XCOPY_TARGET_DESC_LEN;
			cscd_index++;
			break;
		default:
			pr_err("XCOPY unsupported descriptor type code:"
					" 0x%02x\n", desc[0]);
			*sense_ret = TCM_UNSUPPORTED_TARGET_DESC_TYPE_CODE;
			goto out;
		}
	}

	switch (xop->op_origin) {
	case XCOL_SOURCE_RECV_OP:
		/*
		 * Fix CVE-2020-28374
		 *  -2 lines, +4 lines
		 */
		rc = klpp_target_xcopy_locate_se_dev_e4(se_cmd->se_sess,
						xop->dst_tid_wwn,
						&xop->dst_dev,
						remote_lun_ref);
		break;
	case XCOL_DEST_RECV_OP:
		/*
		 * Fix CVE-2020-28374
		 *  -2 lines, +4 lines
		 */
		rc = klpp_target_xcopy_locate_se_dev_e4(se_cmd->se_sess,
						xop->src_tid_wwn,
						&xop->src_dev,
						remote_lun_ref);
		break;
	default:
		pr_err("XCOPY CSCD descriptor IDs not found in CSCD list - "
			"stdi: %hu dtdi: %hu\n", xop->stdi, xop->dtdi);
		rc = -EINVAL;
		break;
	}
	/*
	 * If a matching IEEE NAA 0x83 descriptor for the requested device
	 * is not located on this node, return COPY_ABORTED with ASQ/ASQC
	 * 0x0d/0x02 - COPY_TARGET_DEVICE_NOT_REACHABLE to request the
	 * initiator to fall back to normal copy method.
	 */
	if (rc < 0) {
		*sense_ret = TCM_COPY_TARGET_DEVICE_NOT_REACHABLE;
		goto out;
	}

	pr_debug("XCOPY TGT desc: Source dev: %p NAA IEEE WWN: 0x%16phN\n",
		 xop->src_dev, &xop->src_tid_wwn[0]);
	pr_debug("XCOPY TGT desc: Dest dev: %p NAA IEEE WWN: 0x%16phN\n",
		 xop->dst_dev, &xop->dst_tid_wwn[0]);

	return cscd_index;

out:
	return -EINVAL;
}

static int target_xcopy_parse_segdesc_02(struct se_cmd *se_cmd, struct xcopy_op *xop,
					unsigned char *p)
{
	unsigned char *desc = p;
	int dc = (desc[1] & 0x02);
	unsigned short desc_len;

	desc_len = get_unaligned_be16(&desc[2]);
	if (desc_len != 0x18) {
		pr_err("XCOPY segment desc 0x02: Illegal desc_len:"
				" %hu\n", desc_len);
		return -EINVAL;
	}

	xop->stdi = get_unaligned_be16(&desc[4]);
	xop->dtdi = get_unaligned_be16(&desc[6]);

	if (xop->stdi > XCOPY_CSCD_DESC_ID_LIST_OFF_MAX ||
	    xop->dtdi > XCOPY_CSCD_DESC_ID_LIST_OFF_MAX) {
		pr_err("XCOPY segment desc 0x02: unsupported CSCD ID > 0x%x; stdi: %hu dtdi: %hu\n",
			XCOPY_CSCD_DESC_ID_LIST_OFF_MAX, xop->stdi, xop->dtdi);
		return -EINVAL;
	}

	pr_debug("XCOPY seg desc 0x02: desc_len: %hu stdi: %hu dtdi: %hu, DC: %d\n",
		desc_len, xop->stdi, xop->dtdi, dc);

	xop->nolb = get_unaligned_be16(&desc[10]);
	xop->src_lba = get_unaligned_be64(&desc[12]);
	xop->dst_lba = get_unaligned_be64(&desc[20]);
	pr_debug("XCOPY seg desc 0x02: nolb: %hu src_lba: %llu dst_lba: %llu\n",
		xop->nolb, (unsigned long long)xop->src_lba,
		(unsigned long long)xop->dst_lba);

	return 0;
}

static int target_xcopy_parse_segment_descriptors(struct se_cmd *se_cmd,
				struct xcopy_op *xop, unsigned char *p,
				unsigned int sdll, sense_reason_t *sense_ret)
{
	unsigned char *desc = p;
	unsigned int start = 0;
	int offset = sdll % XCOPY_SEGMENT_DESC_LEN, rc, ret = 0;

	*sense_ret = TCM_INVALID_PARAMETER_LIST;

	if (offset != 0) {
		pr_err("XCOPY segment descriptor list length is not"
			" multiple of %d\n", XCOPY_SEGMENT_DESC_LEN);
		*sense_ret = TCM_UNSUPPORTED_SEGMENT_DESC_TYPE_CODE;
		return -EINVAL;
	}
	if (sdll > RCR_OP_MAX_SG_DESC_COUNT * XCOPY_SEGMENT_DESC_LEN) {
		pr_err("XCOPY supports %u segment descriptor(s), sdll: %u too"
			" large..\n", RCR_OP_MAX_SG_DESC_COUNT, sdll);
		/* spc4r37 6.4.3.5 SEGMENT DESCRIPTOR LIST LENGTH field */
		*sense_ret = TCM_TOO_MANY_SEGMENT_DESCS;
		return -EINVAL;
	}

	while (start < sdll) {
		/*
		 * Check segment descriptor type code for block -> block
		 */
		switch (desc[0]) {
		case 0x02:
			rc = target_xcopy_parse_segdesc_02(se_cmd, xop, desc);
			if (rc < 0)
				goto out;

			ret++;
			start += XCOPY_SEGMENT_DESC_LEN;
			desc += XCOPY_SEGMENT_DESC_LEN;
			break;
		default:
			pr_err("XCOPY unsupported segment descriptor"
				"type: 0x%02x\n", desc[0]);
			*sense_ret = TCM_UNSUPPORTED_SEGMENT_DESC_TYPE_CODE;
			goto out;
		}
	}

	return ret;

out:
	return -EINVAL;
}

struct xcopy_pt_cmd {
	struct se_cmd se_cmd;
	struct completion xpt_passthrough_sem;
	unsigned char sense_buffer[TRANSPORT_SENSE_BUFFER];
};

static struct se_session (*klpe_xcopy_pt_sess);

/*
 * Fix CVE-2020-28374
 *  -1 line, +2 lines
 */
static void klpp_xcopy_pt_undepend_remotedev(struct xcopy_op *xop,
					     struct percpu_ref *remote_lun_ref)
{
	/*
	 * Fix CVE-2020-28374
	 *  -1 line
	 */

	if (xop->op_origin == XCOL_SOURCE_RECV_OP)
		/*
		 * Fix CVE-2020-28374
		 *  -1 line, +1 line
		 */
		pr_debug("putting dst lun_ref for %p\n", xop->dst_dev);
	else
		/*
		 * Fix CVE-2020-28374
		 *  -1 line, +1 line
		 */
		pr_debug("putting src lun_ref for %p\n", xop->src_dev);

	/*
	 * Fix CVE-2020-28374
	 *  -5 lines, +1 line
	 */
	percpu_ref_put(remote_lun_ref);
}

static const struct target_core_fabric_ops (*klpe_xcopy_pt_tfo);

static int (*klpe_target_xcopy_setup_pt_cmd)(
	struct xcopy_pt_cmd *xpt_cmd,
	struct xcopy_op *xop,
	struct se_device *se_dev,
	unsigned char *cdb,
	bool remote_port);

static int (*klpe_target_xcopy_issue_pt_cmd)(struct xcopy_pt_cmd *xpt_cmd);

static int klpr_target_xcopy_read_source(
	struct se_cmd *ec_cmd,
	struct xcopy_op *xop,
	struct se_device *src_dev,
	sector_t src_lba,
	u32 src_sectors)
{
	struct xcopy_pt_cmd xpt_cmd;
	struct se_cmd *se_cmd = &xpt_cmd.se_cmd;
	u32 length = (src_sectors * src_dev->dev_attrib.block_size);
	int rc;
	unsigned char cdb[16];
	bool remote_port = (xop->op_origin == XCOL_DEST_RECV_OP);

	memset(&xpt_cmd, 0, sizeof(xpt_cmd));
	init_completion(&xpt_cmd.xpt_passthrough_sem);

	memset(&cdb[0], 0, 16);
	cdb[0] = READ_16;
	put_unaligned_be64(src_lba, &cdb[2]);
	put_unaligned_be32(src_sectors, &cdb[10]);
	pr_debug("XCOPY: Built READ_16: LBA: %llu Sectors: %u Length: %u\n",
		(unsigned long long)src_lba, src_sectors, length);

	(*klpe_transport_init_se_cmd)(se_cmd, &(*klpe_xcopy_pt_tfo), &(*klpe_xcopy_pt_sess), length,
			      DMA_FROM_DEVICE, 0, &xpt_cmd.sense_buffer[0]);

	rc = (*klpe_target_xcopy_setup_pt_cmd)(&xpt_cmd, xop, src_dev, &cdb[0],
				remote_port);
	if (rc < 0) {
		ec_cmd->scsi_status = se_cmd->scsi_status;
		goto out;
	}

	pr_debug("XCOPY-READ: Saved xop->xop_data_sg: %p, num: %u for READ"
		" memory\n", xop->xop_data_sg, xop->xop_data_nents);

	rc = (*klpe_target_xcopy_issue_pt_cmd)(&xpt_cmd);
	if (rc < 0)
		ec_cmd->scsi_status = se_cmd->scsi_status;
out:
	(*klpe_transport_generic_free_cmd)(se_cmd, 0);
	return rc;
}

static int klpr_target_xcopy_write_destination(
	struct se_cmd *ec_cmd,
	struct xcopy_op *xop,
	struct se_device *dst_dev,
	sector_t dst_lba,
	u32 dst_sectors)
{
	struct xcopy_pt_cmd xpt_cmd;
	struct se_cmd *se_cmd = &xpt_cmd.se_cmd;
	u32 length = (dst_sectors * dst_dev->dev_attrib.block_size);
	int rc;
	unsigned char cdb[16];
	bool remote_port = (xop->op_origin == XCOL_SOURCE_RECV_OP);

	memset(&xpt_cmd, 0, sizeof(xpt_cmd));
	init_completion(&xpt_cmd.xpt_passthrough_sem);

	memset(&cdb[0], 0, 16);
	cdb[0] = WRITE_16;
	put_unaligned_be64(dst_lba, &cdb[2]);
	put_unaligned_be32(dst_sectors, &cdb[10]);
	pr_debug("XCOPY: Built WRITE_16: LBA: %llu Sectors: %u Length: %u\n",
		(unsigned long long)dst_lba, dst_sectors, length);

	(*klpe_transport_init_se_cmd)(se_cmd, &(*klpe_xcopy_pt_tfo), &(*klpe_xcopy_pt_sess), length,
			      DMA_TO_DEVICE, 0, &xpt_cmd.sense_buffer[0]);

	rc = (*klpe_target_xcopy_setup_pt_cmd)(&xpt_cmd, xop, dst_dev, &cdb[0],
				remote_port);
	if (rc < 0) {
		ec_cmd->scsi_status = se_cmd->scsi_status;
		goto out;
	}

	rc = (*klpe_target_xcopy_issue_pt_cmd)(&xpt_cmd);
	if (rc < 0)
		ec_cmd->scsi_status = se_cmd->scsi_status;
out:
	(*klpe_transport_generic_free_cmd)(se_cmd, 0);
	return rc;
}

void klpp_target_xcopy_do_work(struct work_struct *work)
{
	struct xcopy_op *xop = container_of(work, struct xcopy_op, xop_work);
	struct se_cmd *ec_cmd = xop->xop_se_cmd;
	struct se_device *src_dev, *dst_dev;
	sector_t src_lba, dst_lba, end_lba;
	unsigned int max_sectors;
	int rc = 0;
	unsigned short nolb, max_nolb, copied_nolb = 0;
	/*
	 * Fix CVE-2020-28374
	 *  +1 line
	 */
	struct percpu_ref *remote_lun_ref;

	/*
	 * Fix CVE-2020-28374
	 *  -1 line, +1 line
	 */
	if (klpp_target_parse_xcopy_cmd(xop, &remote_lun_ref) != TCM_NO_SENSE)
		goto err_free;

	if (WARN_ON_ONCE(!xop->src_dev) || WARN_ON_ONCE(!xop->dst_dev))
		goto err_free;

	src_dev = xop->src_dev;
	dst_dev = xop->dst_dev;
	src_lba = xop->src_lba;
	dst_lba = xop->dst_lba;
	nolb = xop->nolb;
	end_lba = src_lba + nolb;
	/*
	 * Break up XCOPY I/O into hw_max_sectors sized I/O based on the
	 * smallest max_sectors between src_dev + dev_dev, or
	 */
	max_sectors = min(src_dev->dev_attrib.hw_max_sectors,
			  dst_dev->dev_attrib.hw_max_sectors);
	max_sectors = min_t(u32, max_sectors, XCOPY_MAX_SECTORS);

	max_nolb = min_t(u16, max_sectors, ((u16)(~0U)));

	pr_debug("target_xcopy_do_work: nolb: %hu, max_nolb: %hu end_lba: %llu\n",
			nolb, max_nolb, (unsigned long long)end_lba);
	pr_debug("target_xcopy_do_work: Starting src_lba: %llu, dst_lba: %llu\n",
			(unsigned long long)src_lba, (unsigned long long)dst_lba);

	while (src_lba < end_lba) {
		unsigned short cur_nolb = min(nolb, max_nolb);
		u32 cur_bytes = cur_nolb * src_dev->dev_attrib.block_size;

		if (cur_bytes != xop->xop_data_bytes) {
			/*
			 * (Re)allocate a buffer large enough to hold the XCOPY
			 * I/O size, which can be reused each read / write loop.
			 */
			(*klpe_target_free_sgl)(xop->xop_data_sg, xop->xop_data_nents);
			rc = (*klpe_target_alloc_sgl)(&xop->xop_data_sg,
					      &xop->xop_data_nents,
					      cur_bytes,
					      false, false);
			if (rc < 0)
				goto out;
			xop->xop_data_bytes = cur_bytes;
		}

		pr_debug("target_xcopy_do_work: Calling read src_dev: %p src_lba: %llu,"
			" cur_nolb: %hu\n", src_dev, (unsigned long long)src_lba, cur_nolb);

		rc = klpr_target_xcopy_read_source(ec_cmd, xop, src_dev, src_lba, cur_nolb);
		if (rc < 0)
			goto out;

		src_lba += cur_nolb;
		pr_debug("target_xcopy_do_work: Incremented READ src_lba to %llu\n",
				(unsigned long long)src_lba);

		pr_debug("target_xcopy_do_work: Calling write dst_dev: %p dst_lba: %llu,"
			" cur_nolb: %hu\n", dst_dev, (unsigned long long)dst_lba, cur_nolb);

		rc = klpr_target_xcopy_write_destination(ec_cmd, xop, dst_dev,
						dst_lba, cur_nolb);
		if (rc < 0)
			goto out;

		dst_lba += cur_nolb;
		pr_debug("target_xcopy_do_work: Incremented WRITE dst_lba to %llu\n",
				(unsigned long long)dst_lba);

		copied_nolb += cur_nolb;
		nolb -= cur_nolb;
	}

	/*
	 * Fix CVE-2020-28374
	 *  -1 line, +1 line
	 */
	klpp_xcopy_pt_undepend_remotedev(xop, remote_lun_ref);
	(*klpe_target_free_sgl)(xop->xop_data_sg, xop->xop_data_nents);
	kfree(xop);

	pr_debug("target_xcopy_do_work: Final src_lba: %llu, dst_lba: %llu\n",
		(unsigned long long)src_lba, (unsigned long long)dst_lba);
	pr_debug("target_xcopy_do_work: Blocks copied: %hu, Bytes Copied: %u\n",
		copied_nolb, copied_nolb * dst_dev->dev_attrib.block_size);

	pr_debug("target_xcopy_do_work: Setting X-COPY GOOD status -> sending response\n");
	(*klpe_target_complete_cmd)(ec_cmd, SAM_STAT_GOOD);
	return;

out:
	/*
	 * Fix CVE-2020-28374
	 *  -1 line, +1 line
	 */
	klpp_xcopy_pt_undepend_remotedev(xop, remote_lun_ref);
	(*klpe_target_free_sgl)(xop->xop_data_sg, xop->xop_data_nents);

err_free:
	kfree(xop);
	/*
	 * Don't override an error scsi status if it has already been set
	 */
	if (ec_cmd->scsi_status == SAM_STAT_GOOD) {
		pr_warn_ratelimited("target_xcopy_do_work: rc: %d, Setting X-COPY"
			" CHECK_CONDITION -> sending response\n", rc);
		ec_cmd->scsi_status = SAM_STAT_CHECK_CONDITION;
	}
	(*klpe_target_complete_cmd)(ec_cmd, ec_cmd->scsi_status);
}

/*
 * Fix CVE-2020-28374
 *  -1 line, +2 lines
 */
static sense_reason_t klpp_target_parse_xcopy_cmd(struct xcopy_op *xop,
					     struct percpu_ref **remote_lun_ref)
{
	struct se_cmd *se_cmd = xop->xop_se_cmd;
	unsigned char *p = NULL, *seg_desc;
	unsigned int list_id, list_id_usage, sdll, inline_dl;
	sense_reason_t ret = TCM_INVALID_PARAMETER_LIST;
	int rc;
	unsigned short tdll;

	p = (*klpe_transport_kmap_data_sg)(se_cmd);
	if (!p) {
		pr_err("transport_kmap_data_sg() failed in target_do_xcopy\n");
		return TCM_OUT_OF_RESOURCES;
	}

	list_id = p[0];
	list_id_usage = (p[1] & 0x18) >> 3;

	/*
	 * Determine TARGET DESCRIPTOR LIST LENGTH + SEGMENT DESCRIPTOR LIST LENGTH
	 */
	tdll = get_unaligned_be16(&p[2]);
	sdll = get_unaligned_be32(&p[8]);
	if (tdll + sdll > RCR_OP_MAX_DESC_LIST_LEN) {
		pr_err("XCOPY descriptor list length %u exceeds maximum %u\n",
		       tdll + sdll, RCR_OP_MAX_DESC_LIST_LEN);
		ret = TCM_PARAMETER_LIST_LENGTH_ERROR;
		goto out;
	}

	inline_dl = get_unaligned_be32(&p[12]);
	if (inline_dl != 0) {
		pr_err("XCOPY with non zero inline data length\n");
		goto out;
	}

	if (se_cmd->data_length < (XCOPY_HDR_LEN + tdll + sdll + inline_dl)) {
		pr_err("XCOPY parameter truncation: data length %u too small "
			"for tdll: %hu sdll: %u inline_dl: %u\n",
			se_cmd->data_length, tdll, sdll, inline_dl);
		ret = TCM_PARAMETER_LIST_LENGTH_ERROR;
		goto out;
	}

	pr_debug("Processing XCOPY with list_id: 0x%02x list_id_usage: 0x%02x"
		" tdll: %hu sdll: %u inline_dl: %u\n", list_id, list_id_usage,
		tdll, sdll, inline_dl);

	/*
	 * skip over the target descriptors until segment descriptors
	 * have been passed - CSCD ids are needed to determine src and dest.
	 */
	seg_desc = &p[16] + tdll;

	rc = target_xcopy_parse_segment_descriptors(se_cmd, xop, seg_desc,
						    sdll, &ret);
	if (rc <= 0)
		goto out;

	pr_debug("XCOPY: Processed %d segment descriptors, length: %u\n", rc,
				rc * XCOPY_SEGMENT_DESC_LEN);

	/*
	 * Fix CVE-2020-28374
	 *  -1 line, +2 lines
	 */
	rc = klpp_target_xcopy_parse_target_descriptors(se_cmd, xop, &p[16], tdll,
							&ret, remote_lun_ref);
	if (rc <= 0)
		goto out;

	if (xop->src_dev->dev_attrib.block_size !=
	    xop->dst_dev->dev_attrib.block_size) {
		pr_err("XCOPY: Non matching src_dev block_size: %u + dst_dev"
		       " block_size: %u currently unsupported\n",
			xop->src_dev->dev_attrib.block_size,
			xop->dst_dev->dev_attrib.block_size);
		/*
		 * Fix CVE-2020-28374
		 *  -1 line, +1 line
		 */
		klpp_xcopy_pt_undepend_remotedev(xop, *remote_lun_ref);
		ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		goto out;
	}

	pr_debug("XCOPY: Processed %d target descriptors, length: %u\n", rc,
				rc * XCOPY_TARGET_DESC_LEN);
	(*klpe_transport_kunmap_data_sg)(se_cmd);
	return TCM_NO_SENSE;

out:
	if (p)
		(*klpe_transport_kunmap_data_sg)(se_cmd);
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1178684.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "target_core_mod"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "xcopy_pt_sess", (void *)&klpe_xcopy_pt_sess, "target_core_mod" },
	{ "xcopy_pt_tfo", (void *)&klpe_xcopy_pt_tfo, "target_core_mod" },
	{ "transport_init_se_cmd", (void *)&klpe_transport_init_se_cmd,
	  "target_core_mod" },
	{ "transport_generic_free_cmd",
	  (void *)&klpe_transport_generic_free_cmd, "target_core_mod" },
	{ "target_alloc_sgl", (void *)&klpe_target_alloc_sgl,
	  "target_core_mod" },
	{ "target_free_sgl", (void *)&klpe_target_free_sgl, "target_core_mod" },
	{ "spc_parse_naa_6h_vendor_specific",
	  (void *)&klpe_spc_parse_naa_6h_vendor_specific, "target_core_mod" },
	{ "target_for_each_device", (void *)&klpe_target_for_each_device,
	  "target_core_mod" },
	{ "target_xcopy_setup_pt_cmd", (void *)&klpe_target_xcopy_setup_pt_cmd,
	  "target_core_mod" },
	{ "target_xcopy_issue_pt_cmd", (void *)&klpe_target_xcopy_issue_pt_cmd,
	  "target_core_mod" },
	{ "target_complete_cmd", (void *)&klpe_target_complete_cmd,
	  "target_core_mod" },
	{ "transport_kmap_data_sg", (void *)&klpe_transport_kmap_data_sg,
	  "target_core_mod" },
	{ "transport_kunmap_data_sg", (void *)&klpe_transport_kunmap_data_sg,
	  "target_core_mod" },
};

static int livepatch_bsc1178684_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1178684_module_nb = {
	.notifier_call = livepatch_bsc1178684_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1178684_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1178684_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1178684_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1178684_module_nb);
}
