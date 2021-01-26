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
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/timer.h>

#define MT_QUIRK_CONFIDENCE		BIT(7)

#define MT_QUIRK_NO_AREA		BIT(9)

#define MT_QUIRK_HOVERING		BIT(11)

#define MT_QUIRK_ASUS_CUSTOM_UP		BIT(17)
#define MT_QUIRK_WIN8_PTP_BUTTONS	BIT(18)

#define MT_INPUTMODE_TOUCHPAD		0x03

struct mt_usages {
	struct list_head list;
	__s32 *x, *y, *cx, *cy, *p, *w, *h, *a;
	__s32 *contactid;	/* the device ContactID assigned to this slot */
	bool *tip_state;	/* is the touch valid? */
	bool *inrange_state;	/* is the finger in proximity of the sensor? */
	bool *confidence_state;	/* is the touch made by a finger? */
};

struct mt_application {
	struct list_head list;
	unsigned int application;
	struct list_head mt_usages;	/* mt usages list */

	__s32 quirks;

	__s32 *scantime;		/* scantime reported */
	__s32 scantime_logical_max;	/* max value for raw scantime */

	__s32 *raw_cc;			/* contact count in the report */
	int left_button_state;		/* left button state */
	unsigned int mt_flags;		/* flags to pass to input-mt */

	unsigned long *pending_palm_slots;	/* slots where we reported palm
						 * and need to release */

	__u8 num_received;	/* how many contacts we received */
	__u8 num_expected;	/* expected last contact index */
	__u8 buttons_count;	/* number of physical buttons per touchpad */
	__u8 touches_by_report;	/* how many touches are present in one report:
				 * 1 means we should use a serial protocol
				 * > 1 means hybrid (multitouch) protocol
				 */

	__s32 dev_time;		/* the scan time provided by the device */
	unsigned long jiffies;	/* the frame's jiffies */
	int timestamp;		/* the timestamp to be sent */
	int prev_scantime;		/* scantime reported previously */

	bool have_contact_count;
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

struct mt_report_data {
	struct list_head list;
	struct hid_report *report;
	struct mt_application *application;
	bool is_mt_collection;
};

struct mt_device {
	struct mt_class mtclass;	/* our mt device class */
	struct timer_list release_timer;	/* to release sticky fingers */
	struct hid_device *hdev;	/* hid_device we're attached to */
	unsigned long mt_io_flags;	/* mt flags (MT_IO_FLAGS_*) */
	__u8 inputmode_value;	/* InputMode HID feature value */
	__u8 maxcontacts;
	bool is_buttonpad;	/* is this device a button pad? */
	bool serial_maybe;	/* need to check for serial protocol */

	struct list_head applications;
	struct list_head reports;
};

#define MT_CLS_WIN_8				0x0012

#define MT_CLS_WIN_8_DUAL			0x0014

static void (*klpe_set_abs)(struct input_dev *input, unsigned int code,
		struct hid_field *field, int snratio);

static struct mt_report_data *(*klpe_mt_find_report_data)(struct mt_device *td,
						  struct hid_report *report);

static void (*klpe_mt_store_field)(struct hid_device *hdev,
			   struct mt_application *application,
			   __s32 *value,
			   size_t offset);

#define KLPR_MT_STORE_FIELD(__name)						\
	(*klpe_mt_store_field)(hdev, app,				\
		       &field->value[usage->usage_index],		\
		       offsetof(struct mt_usages, __name))

static int klpp_mt_touch_input_mapping(struct hid_device *hdev, struct hid_input *hi,
		struct hid_field *field, struct hid_usage *usage,
		unsigned long **bit, int *max, struct mt_application *app)
{
	struct mt_device *td = hid_get_drvdata(hdev);
	struct mt_class *cls = &td->mtclass;
	int code;
	struct hid_usage *prev_usage = NULL;

	/*
	 * Model touchscreens providing buttons as touchpads.
	 */
	if (field->application == HID_DG_TOUCHSCREEN &&
	    (usage->hid & HID_USAGE_PAGE) == HID_UP_BUTTON) {
		app->mt_flags |= INPUT_MT_POINTER;
		td->inputmode_value = MT_INPUTMODE_TOUCHPAD;
	}

	/* count the buttons on touchpads */
	if ((usage->hid & HID_USAGE_PAGE) == HID_UP_BUTTON)
		app->buttons_count++;

	if (usage->usage_index)
		prev_usage = &field->usage[usage->usage_index - 1];

	switch (usage->hid & HID_USAGE_PAGE) {

	case HID_UP_GENDESK:
		switch (usage->hid) {
		case HID_GD_X:
			if (prev_usage && (prev_usage->hid == usage->hid)) {
				code = ABS_MT_TOOL_X;
				KLPR_MT_STORE_FIELD(cx);
			} else {
				code = ABS_MT_POSITION_X;
				KLPR_MT_STORE_FIELD(x);
			}

			(*klpe_set_abs)(hi->input, code, field, cls->sn_move);

			/*
			 * A system multi-axis that exports X and Y has a high
			 * chance of being used directly on a surface
			 */
			if (field->application == HID_GD_SYSTEM_MULTIAXIS) {
				__set_bit(INPUT_PROP_DIRECT,
					  hi->input->propbit);
				input_set_abs_params(hi->input,
						     ABS_MT_TOOL_TYPE,
						     MT_TOOL_DIAL,
						     MT_TOOL_DIAL, 0, 0);
			}

			return 1;
		case HID_GD_Y:
			if (prev_usage && (prev_usage->hid == usage->hid)) {
				code = ABS_MT_TOOL_Y;
				KLPR_MT_STORE_FIELD(cy);
			} else {
				code = ABS_MT_POSITION_Y;
				KLPR_MT_STORE_FIELD(y);
			}

			(*klpe_set_abs)(hi->input, code, field, cls->sn_move);

			return 1;
		}
		return 0;

	case HID_UP_DIGITIZER:
		switch (usage->hid) {
		case HID_DG_INRANGE:
			if (app->quirks & MT_QUIRK_HOVERING) {
				input_set_abs_params(hi->input,
					ABS_MT_DISTANCE, 0, 1, 0, 0);
			}
			KLPR_MT_STORE_FIELD(inrange_state);
			return 1;
		case HID_DG_CONFIDENCE:
			if ((cls->name == MT_CLS_WIN_8 ||
				cls->name == MT_CLS_WIN_8_DUAL) &&
				(field->application == HID_DG_TOUCHPAD ||
				 field->application == HID_DG_TOUCHSCREEN))
				app->quirks |= MT_QUIRK_CONFIDENCE;

			if (app->quirks & MT_QUIRK_CONFIDENCE)
				input_set_abs_params(hi->input,
						     ABS_MT_TOOL_TYPE,
						     MT_TOOL_FINGER,
						     MT_TOOL_PALM, 0, 0);

			KLPR_MT_STORE_FIELD(confidence_state);
			return 1;
		case HID_DG_TIPSWITCH:
			if (field->application != HID_GD_SYSTEM_MULTIAXIS)
				input_set_capability(hi->input,
						     EV_KEY, BTN_TOUCH);
			KLPR_MT_STORE_FIELD(tip_state);
			return 1;
		case HID_DG_CONTACTID:
			KLPR_MT_STORE_FIELD(contactid);
			app->touches_by_report++;
			return 1;
		case HID_DG_WIDTH:
			if (!(app->quirks & MT_QUIRK_NO_AREA))
				(*klpe_set_abs)(hi->input, ABS_MT_TOUCH_MAJOR, field,
					cls->sn_width);
			KLPR_MT_STORE_FIELD(w);
			return 1;
		case HID_DG_HEIGHT:
			if (!(app->quirks & MT_QUIRK_NO_AREA)) {
				(*klpe_set_abs)(hi->input, ABS_MT_TOUCH_MINOR, field,
					cls->sn_height);

				/*
				 * Only set ABS_MT_ORIENTATION if it is not
				 * already set by the HID_DG_AZIMUTH usage.
				 */
				if (!test_bit(ABS_MT_ORIENTATION,
						hi->input->absbit))
					input_set_abs_params(hi->input,
						ABS_MT_ORIENTATION, 0, 1, 0, 0);
			}
			KLPR_MT_STORE_FIELD(h);
			return 1;
		case HID_DG_TIPPRESSURE:
			(*klpe_set_abs)(hi->input, ABS_MT_PRESSURE, field,
				cls->sn_pressure);
			KLPR_MT_STORE_FIELD(p);
			return 1;
		case HID_DG_SCANTIME:
			input_set_capability(hi->input, EV_MSC, MSC_TIMESTAMP);
			app->scantime = &field->value[usage->usage_index];
			app->scantime_logical_max = field->logical_maximum;
			return 1;
		case HID_DG_CONTACTCOUNT:
			app->have_contact_count = true;
			app->raw_cc = &field->value[usage->usage_index];
			return 1;
		case HID_DG_AZIMUTH:
			/*
			 * Azimuth has the range of [0, MAX) representing a full
			 * revolution. Set ABS_MT_ORIENTATION to a quarter of
			 * MAX according the definition of ABS_MT_ORIENTATION
			 */
			input_set_abs_params(hi->input, ABS_MT_ORIENTATION,
				-field->logical_maximum / 4,
				field->logical_maximum / 4,
				cls->sn_move ?
				field->logical_maximum / cls->sn_move : 0, 0);
			KLPR_MT_STORE_FIELD(a);
			return 1;
		case HID_DG_CONTACTMAX:
			/* contact max are global to the report */
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
		if ((app->quirks & MT_QUIRK_WIN8_PTP_BUTTONS) &&
		    field->application == HID_DG_TOUCHPAD &&
		    (usage->hid & HID_USAGE) > 1)
			code--;

		if (field->application == HID_GD_SYSTEM_MULTIAXIS)
			code = BTN_0  + ((usage->hid - 1) & HID_USAGE);

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

#define klpp_mt_map_key_clear(c)	klpp_hid_map_usage_clear(hi, usage, bit, \
						    max, EV_KEY, (c))

int klpp_mt_input_mapping(struct hid_device *hdev, struct hid_input *hi,
		struct hid_field *field, struct hid_usage *usage,
		unsigned long **bit, int *max)
{
	struct mt_device *td = hid_get_drvdata(hdev);
	struct mt_application *application;
	struct mt_report_data *rdata;

	rdata = (*klpe_mt_find_report_data)(td, field->report);
	if (!rdata) {
		hid_err(hdev, "failed to allocate data for report\n");
		return 0;
	}

	application = rdata->application;

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
	    field->application != HID_GD_SYSTEM_CONTROL &&
	    field->application != HID_CP_CONSUMER_CONTROL &&
	    field->application != HID_GD_WIRELESS_RADIO_CTLS &&
	    field->application != HID_GD_SYSTEM_MULTIAXIS &&
	    !(field->application == HID_VD_ASUS_CUSTOM_MEDIA_KEYS &&
	      application->quirks & MT_QUIRK_ASUS_CUSTOM_UP))
		return -1;

	/*
	 * Some Asus keyboard+touchpad devices have the hotkeys defined in the
	 * touchpad report descriptor. We need to treat these as an array to
	 * map usages to input keys.
	 */
	if (field->application == HID_VD_ASUS_CUSTOM_MEDIA_KEYS &&
	    application->quirks & MT_QUIRK_ASUS_CUSTOM_UP &&
	    (usage->hid & HID_USAGE_PAGE) == HID_UP_CUSTOM) {
		set_bit(EV_REP, hi->input->evbit);
		if (field->flags & HID_MAIN_ITEM_VARIABLE)
			field->flags &= ~HID_MAIN_ITEM_VARIABLE;
		switch (usage->hid & HID_USAGE) {
		case 0x10: klpp_mt_map_key_clear(KEY_BRIGHTNESSDOWN);	break;
		case 0x20: klpp_mt_map_key_clear(KEY_BRIGHTNESSUP);		break;
		case 0x35: klpp_mt_map_key_clear(KEY_DISPLAY_OFF);		break;
		case 0x6b: klpp_mt_map_key_clear(KEY_F21);			break;
		case 0x6c: klpp_mt_map_key_clear(KEY_SLEEP);			break;
		default:
			return -1;
		}
		return 1;
	}

	if (rdata->is_mt_collection)
		return klpp_mt_touch_input_mapping(hdev, hi, field, usage, bit, max,
					      application);

	/*
	 * some egalax touchscreens have "application == DG_TOUCHSCREEN"
	 * for the stylus. Overwrite the hid_input application
	 */
	if (field->physical == HID_DG_STYLUS)
		hi->application = HID_DG_STYLUS;

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
	{ "mt_store_field", (void *)&klpe_mt_store_field, "hid_multitouch" },
	{ "mt_find_report_data", (void *)&klpe_mt_find_report_data,
	  "hid_multitouch" },
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
