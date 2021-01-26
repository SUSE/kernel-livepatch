/*
 * bsc1180030_hid_multitouch
 *
 * Fix for CVE-2020-0465, bsc#1180030 (hid-multitouch.c part)
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

#if IS_ENABLED(CONFIG_HID_MULTITOUCH)

#if !IS_MODULE(CONFIG_HID_MULTITOUCH)
#error "Live patch supports only CONFIG_HID_MULTITOUCH=m"
#endif

#include "bsc1180030_common.h"

/* klp-ccp: from drivers/hid/hid-multitouch.c */
#include <linux/slab.h>
#include <linux/input/mt.h>
#include <linux/string.h>

#define MT_QUIRK_CONFIDENCE		(1 << 7)

#define MT_QUIRK_NO_AREA		(1 << 9)

#define MT_QUIRK_HOVERING		(1 << 11)

#define MT_INPUTMODE_TOUCHPAD		0x03

struct mt_slot {
	__s32 x, y, cx, cy, p, w, h;
	__s32 contactid;	/* the device ContactID assigned to this slot */
	bool touch_state;	/* is the touch valid? */
	bool inrange_state;	/* is the finger in proximity of the sensor? */
	bool confidence_state;  /* is the touch made by a finger? */
};

struct mt_class {
	__s32 name;	/* MT_CLS */
	__s32 quirks;
	__s32 sn_move;	/* Signal/noise ratio for move events */
	__s32 sn_width;	/* Signal/noise ratio for width events */
	__s32 sn_height;	/* Signal/noise ratio for height events */
	__s32 sn_pressure;	/* Signal/noise ratio for pressure events */
	__u8 maxcontacts;
	bool is_indirect;	/* true for touchpads */
	bool export_all_inputs;	/* do not ignore mouse, keyboards, etc... */
};

struct mt_fields {
	unsigned usages[HID_MAX_FIELDS];
	unsigned int length;
};

struct mt_device {
	struct mt_slot curdata;	/* placeholder of incoming data */
	struct mt_class mtclass;	/* our mt device class */
	struct mt_fields *fields;	/* temporary placeholder for storing the
					   multitouch fields */
	int cc_index;	/* contact count field index in the report */
	int cc_value_index;	/* contact count value index in the field */
	unsigned last_slot_field;	/* the last field of a slot */
	unsigned mt_report_id;	/* the report ID of the multitouch device */
	unsigned long initial_quirks;	/* initial quirks state */
	__s16 inputmode;	/* InputMode HID feature, -1 if non-existent */
	__s16 inputmode_index;	/* InputMode HID feature index in the report */
	__s16 maxcontact_report_id;	/* Maximum Contact Number HID feature,
				   -1 if non-existent */
	__u8 inputmode_value;  /* InputMode HID feature value */
	__u8 num_received;	/* how many contacts we received */
	__u8 num_expected;	/* expected last contact index */
	__u8 maxcontacts;
	__u8 touches_by_report;	/* how many touches are present in one report:
				* 1 means we should use a serial protocol
				* > 1 means hybrid (multitouch) protocol */
	__u8 buttons_count;	/* number of physical buttons per touchpad */
	bool is_buttonpad;	/* is this device a button pad? */
	bool serial_maybe;	/* need to check for serial protocol */
	bool curvalid;		/* is the current contact valid? */
	unsigned mt_flags;	/* flags to pass to input-mt */
};

#define MT_CLS_WIN_8				0x0012

#define MT_CLS_WIN_8_DUAL			0x0014

static void (*klpe_set_abs)(struct input_dev *input, unsigned int code,
		struct hid_field *field, int snratio);

static void mt_store_field(struct hid_usage *usage, struct mt_device *td,
		struct hid_input *hi)
{
	struct mt_fields *f = td->fields;

	if (f->length >= HID_MAX_FIELDS)
		return;

	f->usages[f->length++] = usage->hid;
}

static int klpp_mt_touch_input_mapping(struct hid_device *hdev, struct hid_input *hi,
		struct hid_field *field, struct hid_usage *usage,
		unsigned long **bit, int *max)
{
	struct mt_device *td = hid_get_drvdata(hdev);
	struct mt_class *cls = &td->mtclass;
	int code;
	struct hid_usage *prev_usage = NULL;

	if (field->application == HID_DG_TOUCHSCREEN)
		td->mt_flags |= INPUT_MT_DIRECT;

	/*
	 * Model touchscreens providing buttons as touchpads.
	 */
	if (field->application == HID_DG_TOUCHPAD ||
	    (usage->hid & HID_USAGE_PAGE) == HID_UP_BUTTON) {
		td->mt_flags |= INPUT_MT_POINTER;
		td->inputmode_value = MT_INPUTMODE_TOUCHPAD;
	}

	/* count the buttons on touchpads */
	if ((usage->hid & HID_USAGE_PAGE) == HID_UP_BUTTON)
		td->buttons_count++;

	if (usage->usage_index)
		prev_usage = &field->usage[usage->usage_index - 1];

	switch (usage->hid & HID_USAGE_PAGE) {

	case HID_UP_GENDESK:
		switch (usage->hid) {
		case HID_GD_X:
			if (prev_usage && (prev_usage->hid == usage->hid)) {
				klpp_hid_map_usage(hi, usage, bit, max,
					EV_ABS, ABS_MT_TOOL_X);
				(*klpe_set_abs)(hi->input, ABS_MT_TOOL_X, field,
					cls->sn_move);
			} else {
				klpp_hid_map_usage(hi, usage, bit, max,
					EV_ABS, ABS_MT_POSITION_X);
				(*klpe_set_abs)(hi->input, ABS_MT_POSITION_X, field,
					cls->sn_move);
			}

			mt_store_field(usage, td, hi);
			return 1;
		case HID_GD_Y:
			if (prev_usage && (prev_usage->hid == usage->hid)) {
				klpp_hid_map_usage(hi, usage, bit, max,
					EV_ABS, ABS_MT_TOOL_Y);
				(*klpe_set_abs)(hi->input, ABS_MT_TOOL_Y, field,
					cls->sn_move);
			} else {
				klpp_hid_map_usage(hi, usage, bit, max,
					EV_ABS, ABS_MT_POSITION_Y);
				(*klpe_set_abs)(hi->input, ABS_MT_POSITION_Y, field,
					cls->sn_move);
			}

			mt_store_field(usage, td, hi);
			return 1;
		}
		return 0;

	case HID_UP_DIGITIZER:
		switch (usage->hid) {
		case HID_DG_INRANGE:
			if (cls->quirks & MT_QUIRK_HOVERING) {
				klpp_hid_map_usage(hi, usage, bit, max,
					EV_ABS, ABS_MT_DISTANCE);
				input_set_abs_params(hi->input,
					ABS_MT_DISTANCE, 0, 1, 0, 0);
			}
			mt_store_field(usage, td, hi);
			return 1;
		case HID_DG_CONFIDENCE:
			if ((cls->name == MT_CLS_WIN_8 ||
				cls->name == MT_CLS_WIN_8_DUAL) &&
				field->application == HID_DG_TOUCHPAD)
				cls->quirks |= MT_QUIRK_CONFIDENCE;
			mt_store_field(usage, td, hi);
			return 1;
		case HID_DG_TIPSWITCH:
			klpp_hid_map_usage(hi, usage, bit, max, EV_KEY, BTN_TOUCH);
			input_set_capability(hi->input, EV_KEY, BTN_TOUCH);
			mt_store_field(usage, td, hi);
			return 1;
		case HID_DG_CONTACTID:
			mt_store_field(usage, td, hi);
			td->touches_by_report++;
			td->mt_report_id = field->report->id;
			return 1;
		case HID_DG_WIDTH:
			klpp_hid_map_usage(hi, usage, bit, max,
					EV_ABS, ABS_MT_TOUCH_MAJOR);
			if (!(cls->quirks & MT_QUIRK_NO_AREA))
				(*klpe_set_abs)(hi->input, ABS_MT_TOUCH_MAJOR, field,
					cls->sn_width);
			mt_store_field(usage, td, hi);
			return 1;
		case HID_DG_HEIGHT:
			klpp_hid_map_usage(hi, usage, bit, max,
					EV_ABS, ABS_MT_TOUCH_MINOR);
			if (!(cls->quirks & MT_QUIRK_NO_AREA)) {
				(*klpe_set_abs)(hi->input, ABS_MT_TOUCH_MINOR, field,
					cls->sn_height);
				input_set_abs_params(hi->input,
					ABS_MT_ORIENTATION, 0, 1, 0, 0);
			}
			mt_store_field(usage, td, hi);
			return 1;
		case HID_DG_TIPPRESSURE:
			klpp_hid_map_usage(hi, usage, bit, max,
					EV_ABS, ABS_MT_PRESSURE);
			(*klpe_set_abs)(hi->input, ABS_MT_PRESSURE, field,
				cls->sn_pressure);
			mt_store_field(usage, td, hi);
			return 1;
		case HID_DG_CONTACTCOUNT:
			/* Ignore if indexes are out of bounds. */
			if (field->index >= field->report->maxfield ||
			    usage->usage_index >= field->report_count)
				return 1;
			td->cc_index = field->index;
			td->cc_value_index = usage->usage_index;
			return 1;
		case HID_DG_CONTACTMAX:
			/* we don't set td->last_slot_field as contactcount and
			 * contact max are global to the report */
			return -1;
		case HID_DG_TOUCH:
			/* Legacy devices use TIPSWITCH and not TOUCH.
			 * Let's just ignore this field. */
			return -1;
		}
		/* let hid-input decide for the others */
		return 0;

	case HID_UP_BUTTON:
		code = BTN_MOUSE + ((usage->hid - 1) & HID_USAGE);
		/*
		 * MS PTP spec says that external buttons left and right have
		 * usages 2 and 3.
		 */
		if ((cls->name == MT_CLS_WIN_8 ||
			cls->name == MT_CLS_WIN_8_DUAL) &&
		    field->application == HID_DG_TOUCHPAD &&
		    (usage->hid & HID_USAGE) > 1)
			code--;
		klpp_hid_map_usage(hi, usage, bit, max, EV_KEY, code);
		/*
		 * Fix CVE-2020-0465
		 *  +2 lines
		 */
		if (!*bit)
			return -1;
		input_set_capability(hi->input, EV_KEY, code);
		return 1;

	case 0xff000000:
		/* we do not want to map these: no input-oriented meaning */
		return -1;
	}

	return 0;
}

int klpp_mt_input_mapping(struct hid_device *hdev, struct hid_input *hi,
		struct hid_field *field, struct hid_usage *usage,
		unsigned long **bit, int *max)
{
	struct mt_device *td = hid_get_drvdata(hdev);

	/*
	 * If mtclass.export_all_inputs is not set, only map fields from
	 * TouchScreen or TouchPad collections. We need to ignore fields
	 * that belong to other collections such as Mouse that might have
	 * the same GenericDesktop usages.
	 */
	if (!td->mtclass.export_all_inputs &&
	    field->application != HID_DG_TOUCHSCREEN &&
	    field->application != HID_DG_PEN &&
	    field->application != HID_DG_TOUCHPAD &&
	    field->application != HID_GD_KEYBOARD &&
	    field->application != HID_CP_CONSUMER_CONTROL)
		return -1;

	/*
	 * some egalax touchscreens have "application == HID_DG_TOUCHSCREEN"
	 * for the stylus.
	 * The check for mt_report_id ensures we don't process
	 * HID_DG_CONTACTCOUNT from the pen report as it is outside the physical
	 * collection, but within the report ID.
	 */
	if (field->physical == HID_DG_STYLUS)
		return 0;
	else if ((field->physical == 0) &&
		 (field->report->id != td->mt_report_id) &&
		 (td->mt_report_id != -1))
		return 0;

	if (field->application == HID_DG_TOUCHSCREEN ||
	    field->application == HID_DG_TOUCHPAD)
		return klpp_mt_touch_input_mapping(hdev, hi, field, usage, bit, max);

	/* let hid-core decide for the others */
	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1180030.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "hid_multitouch"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "set_abs", (void *)&klpe_set_abs, "hid_multitouch" },
};

static int
livepatch_bsc1180030_hid_multitouch_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1180030_hid_multitouch_module_nb = {
	.notifier_call = livepatch_bsc1180030_hid_multitouch_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1180030_hid_multitouch_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1180030_hid_multitouch_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1180030_hid_multitouch_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1180030_hid_multitouch_module_nb);
}

#endif /* IS_ENABLED(CONFIG_HID_MULTITOUCH) */
