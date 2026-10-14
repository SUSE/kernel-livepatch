/*
 * bsc1272386_drivers_target_iscsi_iscsi_target_parameters
 *
 * Fix for CVE-2026-63887, bsc#1272386
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


#include "livepatch_bsc1272386.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from drivers/target/iscsi/iscsi_target_parameters.c */
#include <linux/slab.h>
#include <linux/uio.h> /* struct kvec */
#include <target/iscsi/iscsi_target_core.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_util.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h>        /* itt_t */
/* klp-ccp: from drivers/target/iscsi/iscsi_target_parameters.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h>

struct iscsi_extra_response {
	char key[KEY_MAXLEN];
	char value[32];
	struct list_head er_list;
} ____cacheline_aligned;

struct iscsi_param {
	char *name;
	char *value;
	u8 set_param;
	u8 phase;
	u8 scope;
	u8 sender;
	u8 type;
	u8 use;
	u16 type_range;
	u32 state;
	struct list_head p_list;
} ____cacheline_aligned;

static int (*klpe_iscsi_update_param_value)(struct iscsi_param *, char *);
#define YES				"Yes"
#define NO				"No"

#define MAXCONNECTIONS			"MaxConnections"

#define IMMEDIATEDATA			"ImmediateData"
#define MAXRECVDATASEGMENTLENGTH	"MaxRecvDataSegmentLength"

#define MAXBURSTLENGTH			"MaxBurstLength"
#define FIRSTBURSTLENGTH		"FirstBurstLength"

#define MAXOUTSTANDINGR2T		"MaxOutstandingR2T"

#define DATASEQUENCEINORDER		"DataSequenceInOrder"
#define ERRORRECOVERYLEVEL		"ErrorRecoveryLevel"
#define SESSIONTYPE			"SessionType"

#define NORMAL				"Normal"

#define PHASE_DECLARATIVE		0x04

#define IS_PHASE_DECLARATIVE(p)		((p)->phase & PHASE_DECLARATIVE)

#define TYPE_BOOL_AND			0x01
#define TYPE_BOOL_OR			0x02
#define TYPE_NUMBER			0x04

#define IS_TYPE_BOOL_AND(p)		((p)->type & TYPE_BOOL_AND)
#define IS_TYPE_BOOL_OR(p)		((p)->type & TYPE_BOOL_OR)
#define IS_TYPE_NUMBER(p)		((p)->type & TYPE_NUMBER)

#define PSTATE_ACCEPTOR			0x01
#define PSTATE_NEGOTIATE		0x02
#define PSTATE_PROPOSER			0x04

#define PSTATE_REPLY_OPTIONAL		0x20

#define PSTATE_RESPONSE_SENT		0x80

#define IS_PSTATE_ACCEPTOR(p)		((p)->state & PSTATE_ACCEPTOR)
#define IS_PSTATE_NEGOTIATE(p)		((p)->state & PSTATE_NEGOTIATE)
#define IS_PSTATE_PROPOSER(p)		((p)->state & PSTATE_PROPOSER)

#define IS_PSTATE_REPLY_OPTIONAL(p)	((p)->state & PSTATE_REPLY_OPTIONAL)

#define IS_PSTATE_RESPONSE_SENT(p)	((p)->state & PSTATE_RESPONSE_SENT)

#define SET_PSTATE_PROPOSER(p)		((p)->state |= PSTATE_PROPOSER)

#define SET_PSTATE_REPLY_OPTIONAL(p)	((p)->state |= PSTATE_REPLY_OPTIONAL)

#define SET_PSTATE_RESPONSE_SENT(p)	((p)->state |= PSTATE_RESPONSE_SENT)

/* klp-ccp: from drivers/target/iscsi/iscsi_target_parameters.c */
static void (*klpe_iscsi_release_extra_responses)(struct iscsi_param_list *param_list);
static void iscsi_check_proposer_for_optional_reply(struct iscsi_param *param,
						    bool keys_workaround)
{
	if (IS_TYPE_BOOL_AND(param)) {
		if (!strcmp(param->value, NO))
			SET_PSTATE_REPLY_OPTIONAL(param);
	} else if (IS_TYPE_BOOL_OR(param)) {
		if (!strcmp(param->value, YES))
			SET_PSTATE_REPLY_OPTIONAL(param);

		if (keys_workaround) {
			/*
			 * Required for gPXE iSCSI boot client
			 */
			if (!strcmp(param->name, IMMEDIATEDATA))
				SET_PSTATE_REPLY_OPTIONAL(param);
		}
	} else if (IS_TYPE_NUMBER(param)) {
		if (!strcmp(param->name, MAXRECVDATASEGMENTLENGTH))
			SET_PSTATE_REPLY_OPTIONAL(param);

		if (keys_workaround) {
			/*
			 * Required for Mellanox Flexboot PXE boot ROM
			 */
			if (!strcmp(param->name, FIRSTBURSTLENGTH))
				SET_PSTATE_REPLY_OPTIONAL(param);

			/*
			 * Required for gPXE iSCSI boot client
			 */
			if (!strcmp(param->name, MAXCONNECTIONS))
				SET_PSTATE_REPLY_OPTIONAL(param);
		}
	} else if (IS_PHASE_DECLARATIVE(param))
		SET_PSTATE_REPLY_OPTIONAL(param);
}

static int klpr_iscsi_enforce_integrity_rules(
	u8 phase,
	struct iscsi_param_list *param_list)
{
	char *tmpptr;
	u8 DataSequenceInOrder = 0;
	u8 ErrorRecoveryLevel = 0, SessionType = 0;
	u32 FirstBurstLength = 0, MaxBurstLength = 0;
	struct iscsi_param *param = NULL;

	list_for_each_entry(param, &param_list->param_list, p_list) {
		if (!(param->phase & phase))
			continue;
		if (!strcmp(param->name, SESSIONTYPE))
			if (!strcmp(param->value, NORMAL))
				SessionType = 1;
		if (!strcmp(param->name, ERRORRECOVERYLEVEL))
			ErrorRecoveryLevel = simple_strtoul(param->value,
					&tmpptr, 0);
		if (!strcmp(param->name, DATASEQUENCEINORDER))
			if (!strcmp(param->value, YES))
				DataSequenceInOrder = 1;
		if (!strcmp(param->name, MAXBURSTLENGTH))
			MaxBurstLength = simple_strtoul(param->value,
					&tmpptr, 0);
	}

	list_for_each_entry(param, &param_list->param_list, p_list) {
		if (!(param->phase & phase))
			continue;
		if (!SessionType && !IS_PSTATE_ACCEPTOR(param))
			continue;
		if (!strcmp(param->name, MAXOUTSTANDINGR2T) &&
		    DataSequenceInOrder && (ErrorRecoveryLevel > 0)) {
			if (strcmp(param->value, "1")) {
				if ((*klpe_iscsi_update_param_value)(param, "1") < 0)
					return -1;
				pr_debug("Reset \"%s\" to \"%s\".\n",
					param->name, param->value);
			}
		}
		if (!strcmp(param->name, MAXCONNECTIONS) && !SessionType) {
			if (strcmp(param->value, "1")) {
				if ((*klpe_iscsi_update_param_value)(param, "1") < 0)
					return -1;
				pr_debug("Reset \"%s\" to \"%s\".\n",
					param->name, param->value);
			}
		}
		if (!strcmp(param->name, FIRSTBURSTLENGTH)) {
			FirstBurstLength = simple_strtoul(param->value,
					&tmpptr, 0);
			if (FirstBurstLength > MaxBurstLength) {
				char tmpbuf[11];
				memset(tmpbuf, 0, sizeof(tmpbuf));
				sprintf(tmpbuf, "%u", MaxBurstLength);
				if ((*klpe_iscsi_update_param_value)(param, tmpbuf))
					return -1;
				pr_debug("Reset \"%s\" to \"%s\".\n",
					param->name, param->value);
			}
		}
	}

	return 0;
}

static int iscsi_encode_text_record(char *textbuf, u32 *length,
				    u32 textbuf_size,
				    const char *key, const char *value)
{
	int n;
	u32 avail;

	if (*length >= textbuf_size)
		return -EMSGSIZE;

	avail = textbuf_size - *length;
	n = snprintf(textbuf + *length, avail, "%s=%s", key, value);
	if (n < 0 || (u32)n + 1 > avail)
		return -EMSGSIZE;

	*length += n + 1;
	return 0;
}

int klpp_iscsi_encode_text_output(
	u8 phase,
	u8 sender,
	char *textbuf,
	u32 *length,
	u32 textbuf_size,
	struct iscsi_param_list *param_list,
	bool keys_workaround)
{
	struct iscsi_extra_response *er;
	struct iscsi_param *param;
	int ret;

	if (klpr_iscsi_enforce_integrity_rules(phase, param_list) < 0)
		return -1;

	list_for_each_entry(param, &param_list->param_list, p_list) {
		if (!(param->sender & sender))
			continue;
		if (IS_PSTATE_ACCEPTOR(param) &&
		    !IS_PSTATE_RESPONSE_SENT(param) &&
		    !IS_PSTATE_REPLY_OPTIONAL(param) &&
		    (param->phase & phase)) {
			ret = iscsi_encode_text_record(textbuf, length,
						       textbuf_size,
						       param->name,
						       param->value);
			if (ret < 0)
				goto err_overflow;
			SET_PSTATE_RESPONSE_SENT(param);
			pr_debug("Sending key: %s=%s\n",
				param->name, param->value);
			continue;
		}
		if (IS_PSTATE_NEGOTIATE(param) &&
		    !IS_PSTATE_ACCEPTOR(param) &&
		    !IS_PSTATE_PROPOSER(param) &&
		    (param->phase & phase)) {
			ret = iscsi_encode_text_record(textbuf, length,
						       textbuf_size,
						       param->name,
						       param->value);
			if (ret < 0)
				goto err_overflow;
			SET_PSTATE_PROPOSER(param);
			iscsi_check_proposer_for_optional_reply(param,
							        keys_workaround);
			pr_debug("Sending key: %s=%s\n",
				param->name, param->value);
		}
	}

	list_for_each_entry(er, &param_list->extra_response_list, er_list) {
		ret = iscsi_encode_text_record(textbuf, length, textbuf_size,
					       er->key, er->value);
		if (ret < 0)
			goto err_overflow;
		pr_debug("Sending key: %s=%s\n", er->key, er->value);
	}
	(*klpe_iscsi_release_extra_responses)(param_list);

	return 0;

err_overflow:
	pr_err("iSCSI login response buffer (%u bytes) exhausted, dropping login.\n",
	       textbuf_size);
	(*klpe_iscsi_release_extra_responses)(param_list);
	return -1;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "iscsi_target_mod"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "iscsi_release_extra_responses",
	  (void *)&klpe_iscsi_release_extra_responses, "iscsi_target_mod" },
	{ "iscsi_update_param_value", (void *)&klpe_iscsi_update_param_value,
	  "iscsi_target_mod" },
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

int bsc1272386_drivers_target_iscsi_iscsi_target_parameters_init(void)
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

void bsc1272386_drivers_target_iscsi_iscsi_target_parameters_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
