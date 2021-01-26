/*
 * bsc1180030_hid_input
 *
 * Fix for CVE-2020-0465, bsc#1180030 (hid-input.c part)
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

#if IS_ENABLED(CONFIG_HID)

#include "bsc1180030_common.h"

/* klp-ccp: from drivers/hid/hid-input.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/hid.h>

static const unsigned char (*klpe_hid_keyboard)[256];

#define klpp_map_abs(c)	klpp_hid_map_usage(hidinput, usage, &bit, &max, EV_ABS, (c))
#define klpp_map_rel(c)	klpp_hid_map_usage(hidinput, usage, &bit, &max, EV_REL, (c))
#define klpp_map_key(c)	klpp_hid_map_usage(hidinput, usage, &bit, &max, EV_KEY, (c))
#define klpp_map_led(c)	klpp_hid_map_usage(hidinput, usage, &bit, &max, EV_LED, (c))

#define klpp_map_abs_clear(c)	klpp_hid_map_usage_clear(hidinput, usage, &bit, \
		&max, EV_ABS, (c))
#define klpp_map_key_clear(c)	klpp_hid_map_usage_clear(hidinput, usage, &bit, \
		&max, EV_KEY, (c))

__s32 hidinput_calc_abs_res(const struct hid_field *field, __u16 code);

#ifdef CONFIG_HID_BATTERY_STRENGTH

static int (*klpe_hidinput_setup_battery)(struct hid_device *dev, unsigned report_type, struct hid_field *field);
#define klpr_hidinput_setup_battery (*klpe_hidinput_setup_battery)

#else  /* !CONFIG_HID_BATTERY_STRENGTH */

static int klpr_hidinput_setup_battery(struct hid_device *dev, unsigned report_type,
				  struct hid_field *field)
{
	return 0;
}

#endif	/* CONFIG_HID_BATTERY_STRENGTH */

void klpp_hidinput_configure_usage(struct hid_input *hidinput, struct hid_field *field,
				     struct hid_usage *usage)
{
	struct input_dev *input = hidinput->input;
	struct hid_device *device = input_get_drvdata(input);
	int max = 0, code;
	unsigned long *bit = NULL;

	field->hidinput = hidinput;

	if (field->flags & HID_MAIN_ITEM_CONSTANT)
		goto ignore;

	/* Ignore if report count is out of bounds. */
	if (field->report_count < 1)
		goto ignore;

	/* only LED usages are supported in output fields */
	if (field->report_type == HID_OUTPUT_REPORT &&
			(usage->hid & HID_USAGE_PAGE) != HID_UP_LED) {
		goto ignore;
	}

	if (device->driver->input_mapping) {
		int ret = device->driver->input_mapping(device, hidinput, field,
				usage, &bit, &max);
		if (ret > 0)
			goto mapped;
		if (ret < 0)
			goto ignore;
	}

	switch (usage->hid & HID_USAGE_PAGE) {
	case HID_UP_UNDEFINED:
		goto ignore;

	case HID_UP_KEYBOARD:
		set_bit(EV_REP, input->evbit);

		if ((usage->hid & HID_USAGE) < 256) {
			if (!(*klpe_hid_keyboard)[usage->hid & HID_USAGE]) goto ignore;
			klpp_map_key_clear((*klpe_hid_keyboard)[usage->hid & HID_USAGE]);
		} else
			klpp_map_key(KEY_UNKNOWN);

		break;

	case HID_UP_BUTTON:
		code = ((usage->hid - 1) & HID_USAGE);

		switch (field->application) {
		case HID_GD_MOUSE:
		case HID_GD_POINTER:  code += BTN_MOUSE; break;
		case HID_GD_JOYSTICK:
				if (code <= 0xf)
					code += BTN_JOYSTICK;
				else
					code += BTN_TRIGGER_HAPPY - 0x10;
				break;
		case HID_GD_GAMEPAD:
				if (code <= 0xf)
					code += BTN_GAMEPAD;
				else
					code += BTN_TRIGGER_HAPPY - 0x10;
				break;
		default:
			switch (field->physical) {
			case HID_GD_MOUSE:
			case HID_GD_POINTER:  code += BTN_MOUSE; break;
			case HID_GD_JOYSTICK: code += BTN_JOYSTICK; break;
			case HID_GD_GAMEPAD:  code += BTN_GAMEPAD; break;
			default:              code += BTN_MISC;
			}
		}

		klpp_map_key(code);
		break;

	case HID_UP_SIMULATION:
		switch (usage->hid & 0xffff) {
		case 0xba: klpp_map_abs(ABS_RUDDER);   break;
		case 0xbb: klpp_map_abs(ABS_THROTTLE); break;
		case 0xc4: klpp_map_abs(ABS_GAS);      break;
		case 0xc5: klpp_map_abs(ABS_BRAKE);    break;
		case 0xc8: klpp_map_abs(ABS_WHEEL);    break;
		default:   goto ignore;
		}
		break;

	case HID_UP_GENDESK:
		if ((usage->hid & 0xf0) == 0x80) {	/* SystemControl */
			switch (usage->hid & 0xf) {
			case 0x1: klpp_map_key_clear(KEY_POWER);  break;
			case 0x2: klpp_map_key_clear(KEY_SLEEP);  break;
			case 0x3: klpp_map_key_clear(KEY_WAKEUP); break;
			case 0x4: klpp_map_key_clear(KEY_CONTEXT_MENU); break;
			case 0x5: klpp_map_key_clear(KEY_MENU); break;
			case 0x6: klpp_map_key_clear(KEY_PROG1); break;
			case 0x7: klpp_map_key_clear(KEY_HELP); break;
			case 0x8: klpp_map_key_clear(KEY_EXIT); break;
			case 0x9: klpp_map_key_clear(KEY_SELECT); break;
			case 0xa: klpp_map_key_clear(KEY_RIGHT); break;
			case 0xb: klpp_map_key_clear(KEY_LEFT); break;
			case 0xc: klpp_map_key_clear(KEY_UP); break;
			case 0xd: klpp_map_key_clear(KEY_DOWN); break;
			case 0xe: klpp_map_key_clear(KEY_POWER2); break;
			case 0xf: klpp_map_key_clear(KEY_RESTART); break;
			default: goto unknown;
			}
			break;
		}

		if ((usage->hid & 0xf0) == 0xb0) {	/* SC - Display */
			switch (usage->hid & 0xf) {
			case 0x05: klpp_map_key_clear(KEY_SWITCHVIDEOMODE); break;
			default: goto ignore;
			}
			break;
		}

		/*
		 * Some lazy vendors declare 255 usages for System Control,
		 * leading to the creation of ABS_X|Y axis and too many others.
		 * It wouldn't be a problem if joydev doesn't consider the
		 * device as a joystick then.
		 */
		if (field->application == HID_GD_SYSTEM_CONTROL)
			goto ignore;

		if ((usage->hid & 0xf0) == 0x90) {	/* D-pad */
			switch (usage->hid) {
			case HID_GD_UP:	   usage->hat_dir = 1; break;
			case HID_GD_DOWN:  usage->hat_dir = 5; break;
			case HID_GD_RIGHT: usage->hat_dir = 3; break;
			case HID_GD_LEFT:  usage->hat_dir = 7; break;
			default: goto unknown;
			}
			if (field->dpad) {
				klpp_map_abs(field->dpad);
				goto ignore;
			}
			klpp_map_abs(ABS_HAT0X);
			break;
		}

		switch (usage->hid) {
		/* These usage IDs map directly to the usage codes. */
		case HID_GD_X: case HID_GD_Y: case HID_GD_Z:
		case HID_GD_RX: case HID_GD_RY: case HID_GD_RZ:
			if (field->flags & HID_MAIN_ITEM_RELATIVE)
				klpp_map_rel(usage->hid & 0xf);
			else
				klpp_map_abs_clear(usage->hid & 0xf);
			break;

		case HID_GD_WHEEL:
			if (field->flags & HID_MAIN_ITEM_RELATIVE) {
				set_bit(REL_WHEEL, input->relbit);
				klpp_map_rel(REL_WHEEL_HI_RES);
			} else {
				klpp_map_abs(usage->hid & 0xf);
			}
			break;
		case HID_GD_SLIDER: case HID_GD_DIAL:
			if (field->flags & HID_MAIN_ITEM_RELATIVE)
				klpp_map_rel(usage->hid & 0xf);
			else
				klpp_map_abs(usage->hid & 0xf);
			break;

		case HID_GD_HATSWITCH:
			usage->hat_min = field->logical_minimum;
			usage->hat_max = field->logical_maximum;
			klpp_map_abs(ABS_HAT0X);
			break;

		case HID_GD_START:	klpp_map_key_clear(BTN_START);	break;
		case HID_GD_SELECT:	klpp_map_key_clear(BTN_SELECT);	break;

		case HID_GD_RFKILL_BTN:
			/* MS wireless radio ctl extension, also check CA */
			if (field->application == HID_GD_WIRELESS_RADIO_CTLS) {
				klpp_map_key_clear(KEY_RFKILL);
				/* We need to simulate the btn release */
				field->flags |= HID_MAIN_ITEM_RELATIVE;
				break;
			}

		default: goto unknown;
		}

		break;

	case HID_UP_LED:
		switch (usage->hid & 0xffff) {		      /* HID-Value:                   */
		case 0x01:  klpp_map_led (LED_NUML);     break;    /*   "Num Lock"                 */
		case 0x02:  klpp_map_led (LED_CAPSL);    break;    /*   "Caps Lock"                */
		case 0x03:  klpp_map_led (LED_SCROLLL);  break;    /*   "Scroll Lock"              */
		case 0x04:  klpp_map_led (LED_COMPOSE);  break;    /*   "Compose"                  */
		case 0x05:  klpp_map_led (LED_KANA);     break;    /*   "Kana"                     */
		case 0x27:  klpp_map_led (LED_SLEEP);    break;    /*   "Stand-By"                 */
		case 0x4c:  klpp_map_led (LED_SUSPEND);  break;    /*   "System Suspend"           */
		case 0x09:  klpp_map_led (LED_MUTE);     break;    /*   "Mute"                     */
		case 0x4b:  klpp_map_led (LED_MISC);     break;    /*   "Generic Indicator"        */
		case 0x19:  klpp_map_led (LED_MAIL);     break;    /*   "Message Waiting"          */
		case 0x4d:  klpp_map_led (LED_CHARGING); break;    /*   "External Power Connected" */

		default: goto ignore;
		}
		break;

	case HID_UP_DIGITIZER:
		if ((field->application & 0xff) == 0x01) /* Digitizer */
			__set_bit(INPUT_PROP_POINTER, input->propbit);
		else if ((field->application & 0xff) == 0x02) /* Pen */
			__set_bit(INPUT_PROP_DIRECT, input->propbit);

		switch (usage->hid & 0xff) {
		case 0x00: /* Undefined */
			goto ignore;

		case 0x30: /* TipPressure */
			if (!test_bit(BTN_TOUCH, input->keybit)) {
				device->quirks |= HID_QUIRK_NOTOUCH;
				set_bit(EV_KEY, input->evbit);
				set_bit(BTN_TOUCH, input->keybit);
			}
			klpp_map_abs_clear(ABS_PRESSURE);
			break;

		case 0x32: /* InRange */
			switch (field->physical & 0xff) {
			case 0x21: klpp_map_key(BTN_TOOL_MOUSE); break;
			case 0x22: klpp_map_key(BTN_TOOL_FINGER); break;
			default: klpp_map_key(BTN_TOOL_PEN); break;
			}
			break;

		case 0x3b: /* Battery Strength */
			klpr_hidinput_setup_battery(device, HID_INPUT_REPORT, field);
			usage->type = EV_PWR;
			goto ignore;

		case 0x3c: /* Invert */
			klpp_map_key_clear(BTN_TOOL_RUBBER);
			break;

		case 0x3d: /* X Tilt */
			klpp_map_abs_clear(ABS_TILT_X);
			break;

		case 0x3e: /* Y Tilt */
			klpp_map_abs_clear(ABS_TILT_Y);
			break;

		case 0x33: /* Touch */
		case 0x42: /* TipSwitch */
		case 0x43: /* TipSwitch2 */
			device->quirks &= ~HID_QUIRK_NOTOUCH;
			klpp_map_key_clear(BTN_TOUCH);
			break;

		case 0x44: /* BarrelSwitch */
			klpp_map_key_clear(BTN_STYLUS);
			break;

		case 0x45: /* ERASER */
			/*
			 * This event is reported when eraser tip touches the surface.
			 * Actual eraser (BTN_TOOL_RUBBER) is set by Invert usage when
			 * tool gets in proximity.
			 */
			klpp_map_key_clear(BTN_TOUCH);
			break;

		case 0x46: /* TabletPick */
		case 0x5a: /* SecondaryBarrelSwitch */
			klpp_map_key_clear(BTN_STYLUS2);
			break;

		case 0x5b: /* TransducerSerialNumber */
			usage->type = EV_MSC;
			usage->code = MSC_SERIAL;
			bit = input->mscbit;
			max = MSC_MAX;
			break;

		default:  goto unknown;
		}
		break;

	case HID_UP_TELEPHONY:
		switch (usage->hid & HID_USAGE) {
		case 0x2f: klpp_map_key_clear(KEY_MICMUTE);		break;
		case 0xb0: klpp_map_key_clear(KEY_NUMERIC_0);	break;
		case 0xb1: klpp_map_key_clear(KEY_NUMERIC_1);	break;
		case 0xb2: klpp_map_key_clear(KEY_NUMERIC_2);	break;
		case 0xb3: klpp_map_key_clear(KEY_NUMERIC_3);	break;
		case 0xb4: klpp_map_key_clear(KEY_NUMERIC_4);	break;
		case 0xb5: klpp_map_key_clear(KEY_NUMERIC_5);	break;
		case 0xb6: klpp_map_key_clear(KEY_NUMERIC_6);	break;
		case 0xb7: klpp_map_key_clear(KEY_NUMERIC_7);	break;
		case 0xb8: klpp_map_key_clear(KEY_NUMERIC_8);	break;
		case 0xb9: klpp_map_key_clear(KEY_NUMERIC_9);	break;
		case 0xba: klpp_map_key_clear(KEY_NUMERIC_STAR);	break;
		case 0xbb: klpp_map_key_clear(KEY_NUMERIC_POUND);	break;
		case 0xbc: klpp_map_key_clear(KEY_NUMERIC_A);	break;
		case 0xbd: klpp_map_key_clear(KEY_NUMERIC_B);	break;
		case 0xbe: klpp_map_key_clear(KEY_NUMERIC_C);	break;
		case 0xbf: klpp_map_key_clear(KEY_NUMERIC_D);	break;
		default: goto ignore;
		}
		break;

	case HID_UP_CONSUMER:	/* USB HUT v1.12, pages 75-84 */
		switch (usage->hid & HID_USAGE) {
		case 0x000: goto ignore;
		case 0x030: klpp_map_key_clear(KEY_POWER);		break;
		case 0x031: klpp_map_key_clear(KEY_RESTART);		break;
		case 0x032: klpp_map_key_clear(KEY_SLEEP);		break;
		case 0x034: klpp_map_key_clear(KEY_SLEEP);		break;
		case 0x035: klpp_map_key_clear(KEY_KBDILLUMTOGGLE);	break;
		case 0x036: klpp_map_key_clear(BTN_MISC);		break;

		case 0x040: klpp_map_key_clear(KEY_MENU);		break; /* Menu */
		case 0x041: klpp_map_key_clear(KEY_SELECT);		break; /* Menu Pick */
		case 0x042: klpp_map_key_clear(KEY_UP);		break; /* Menu Up */
		case 0x043: klpp_map_key_clear(KEY_DOWN);		break; /* Menu Down */
		case 0x044: klpp_map_key_clear(KEY_LEFT);		break; /* Menu Left */
		case 0x045: klpp_map_key_clear(KEY_RIGHT);		break; /* Menu Right */
		case 0x046: klpp_map_key_clear(KEY_ESC);		break; /* Menu Escape */
		case 0x047: klpp_map_key_clear(KEY_KPPLUS);		break; /* Menu Value Increase */
		case 0x048: klpp_map_key_clear(KEY_KPMINUS);		break; /* Menu Value Decrease */

		case 0x060: klpp_map_key_clear(KEY_INFO);		break; /* Data On Screen */
		case 0x061: klpp_map_key_clear(KEY_SUBTITLE);	break; /* Closed Caption */
		case 0x063: klpp_map_key_clear(KEY_VCR);		break; /* VCR/TV */
		case 0x065: klpp_map_key_clear(KEY_CAMERA);		break; /* Snapshot */
		case 0x069: klpp_map_key_clear(KEY_RED);		break;
		case 0x06a: klpp_map_key_clear(KEY_GREEN);		break;
		case 0x06b: klpp_map_key_clear(KEY_BLUE);		break;
		case 0x06c: klpp_map_key_clear(KEY_YELLOW);		break;
		case 0x06d: klpp_map_key_clear(KEY_ASPECT_RATIO);	break;

		case 0x06f: klpp_map_key_clear(KEY_BRIGHTNESSUP);		break;
		case 0x070: klpp_map_key_clear(KEY_BRIGHTNESSDOWN);		break;
		case 0x072: klpp_map_key_clear(KEY_BRIGHTNESS_TOGGLE);	break;
		case 0x073: klpp_map_key_clear(KEY_BRIGHTNESS_MIN);		break;
		case 0x074: klpp_map_key_clear(KEY_BRIGHTNESS_MAX);		break;
		case 0x075: klpp_map_key_clear(KEY_BRIGHTNESS_AUTO);		break;

		case 0x079: klpp_map_key_clear(KEY_KBDILLUMUP);	break;
		case 0x07a: klpp_map_key_clear(KEY_KBDILLUMDOWN);	break;
		case 0x07c: klpp_map_key_clear(KEY_KBDILLUMTOGGLE);	break;

		case 0x082: klpp_map_key_clear(KEY_VIDEO_NEXT);	break;
		case 0x083: klpp_map_key_clear(KEY_LAST);		break;
		case 0x084: klpp_map_key_clear(KEY_ENTER);		break;
		case 0x088: klpp_map_key_clear(KEY_PC);		break;
		case 0x089: klpp_map_key_clear(KEY_TV);		break;
		case 0x08a: klpp_map_key_clear(KEY_WWW);		break;
		case 0x08b: klpp_map_key_clear(KEY_DVD);		break;
		case 0x08c: klpp_map_key_clear(KEY_PHONE);		break;
		case 0x08d: klpp_map_key_clear(KEY_PROGRAM);		break;
		case 0x08e: klpp_map_key_clear(KEY_VIDEOPHONE);	break;
		case 0x08f: klpp_map_key_clear(KEY_GAMES);		break;
		case 0x090: klpp_map_key_clear(KEY_MEMO);		break;
		case 0x091: klpp_map_key_clear(KEY_CD);		break;
		case 0x092: klpp_map_key_clear(KEY_VCR);		break;
		case 0x093: klpp_map_key_clear(KEY_TUNER);		break;
		case 0x094: klpp_map_key_clear(KEY_EXIT);		break;
		case 0x095: klpp_map_key_clear(KEY_HELP);		break;
		case 0x096: klpp_map_key_clear(KEY_TAPE);		break;
		case 0x097: klpp_map_key_clear(KEY_TV2);		break;
		case 0x098: klpp_map_key_clear(KEY_SAT);		break;
		case 0x09a: klpp_map_key_clear(KEY_PVR);		break;

		case 0x09c: klpp_map_key_clear(KEY_CHANNELUP);	break;
		case 0x09d: klpp_map_key_clear(KEY_CHANNELDOWN);	break;
		case 0x0a0: klpp_map_key_clear(KEY_VCR2);		break;

		case 0x0b0: klpp_map_key_clear(KEY_PLAY);		break;
		case 0x0b1: klpp_map_key_clear(KEY_PAUSE);		break;
		case 0x0b2: klpp_map_key_clear(KEY_RECORD);		break;
		case 0x0b3: klpp_map_key_clear(KEY_FASTFORWARD);	break;
		case 0x0b4: klpp_map_key_clear(KEY_REWIND);		break;
		case 0x0b5: klpp_map_key_clear(KEY_NEXTSONG);	break;
		case 0x0b6: klpp_map_key_clear(KEY_PREVIOUSSONG);	break;
		case 0x0b7: klpp_map_key_clear(KEY_STOPCD);		break;
		case 0x0b8: klpp_map_key_clear(KEY_EJECTCD);		break;
		case 0x0bc: klpp_map_key_clear(KEY_MEDIA_REPEAT);	break;
		case 0x0b9: klpp_map_key_clear(KEY_SHUFFLE);		break;
		case 0x0bf: klpp_map_key_clear(KEY_SLOW);		break;

		case 0x0cd: klpp_map_key_clear(KEY_PLAYPAUSE);	break;
		case 0x0cf: klpp_map_key_clear(KEY_VOICECOMMAND);	break;
		case 0x0e0: klpp_map_abs_clear(ABS_VOLUME);		break;
		case 0x0e2: klpp_map_key_clear(KEY_MUTE);		break;
		case 0x0e5: klpp_map_key_clear(KEY_BASSBOOST);	break;
		case 0x0e9: klpp_map_key_clear(KEY_VOLUMEUP);	break;
		case 0x0ea: klpp_map_key_clear(KEY_VOLUMEDOWN);	break;
		case 0x0f5: klpp_map_key_clear(KEY_SLOW);		break;

		case 0x181: klpp_map_key_clear(KEY_BUTTONCONFIG);	break;
		case 0x182: klpp_map_key_clear(KEY_BOOKMARKS);	break;
		case 0x183: klpp_map_key_clear(KEY_CONFIG);		break;
		case 0x184: klpp_map_key_clear(KEY_WORDPROCESSOR);	break;
		case 0x185: klpp_map_key_clear(KEY_EDITOR);		break;
		case 0x186: klpp_map_key_clear(KEY_SPREADSHEET);	break;
		case 0x187: klpp_map_key_clear(KEY_GRAPHICSEDITOR);	break;
		case 0x188: klpp_map_key_clear(KEY_PRESENTATION);	break;
		case 0x189: klpp_map_key_clear(KEY_DATABASE);	break;
		case 0x18a: klpp_map_key_clear(KEY_MAIL);		break;
		case 0x18b: klpp_map_key_clear(KEY_NEWS);		break;
		case 0x18c: klpp_map_key_clear(KEY_VOICEMAIL);	break;
		case 0x18d: klpp_map_key_clear(KEY_ADDRESSBOOK);	break;
		case 0x18e: klpp_map_key_clear(KEY_CALENDAR);	break;
		case 0x18f: klpp_map_key_clear(KEY_TASKMANAGER);	break;
		case 0x190: klpp_map_key_clear(KEY_JOURNAL);		break;
		case 0x191: klpp_map_key_clear(KEY_FINANCE);		break;
		case 0x192: klpp_map_key_clear(KEY_CALC);		break;
		case 0x193: klpp_map_key_clear(KEY_PLAYER);		break;
		case 0x194: klpp_map_key_clear(KEY_FILE);		break;
		case 0x196: klpp_map_key_clear(KEY_WWW);		break;
		case 0x199: klpp_map_key_clear(KEY_CHAT);		break;
		case 0x19c: klpp_map_key_clear(KEY_LOGOFF);		break;
		case 0x19e: klpp_map_key_clear(KEY_COFFEE);		break;
		case 0x19f: klpp_map_key_clear(KEY_CONTROLPANEL);		break;
		case 0x1a2: klpp_map_key_clear(KEY_APPSELECT);		break;
		case 0x1a3: klpp_map_key_clear(KEY_NEXT);		break;
		case 0x1a4: klpp_map_key_clear(KEY_PREVIOUS);	break;
		case 0x1a6: klpp_map_key_clear(KEY_HELP);		break;
		case 0x1a7: klpp_map_key_clear(KEY_DOCUMENTS);	break;
		case 0x1ab: klpp_map_key_clear(KEY_SPELLCHECK);	break;
		case 0x1ae: klpp_map_key_clear(KEY_KEYBOARD);	break;
		case 0x1b1: klpp_map_key_clear(KEY_SCREENSAVER);		break;
		case 0x1b4: klpp_map_key_clear(KEY_FILE);		break;
		case 0x1b6: klpp_map_key_clear(KEY_IMAGES);		break;
		case 0x1b7: klpp_map_key_clear(KEY_AUDIO);		break;
		case 0x1b8: klpp_map_key_clear(KEY_VIDEO);		break;
		case 0x1bc: klpp_map_key_clear(KEY_MESSENGER);	break;
		case 0x1bd: klpp_map_key_clear(KEY_INFO);		break;
		case 0x1cb: klpp_map_key_clear(KEY_ASSISTANT);	break;
		case 0x201: klpp_map_key_clear(KEY_NEW);		break;
		case 0x202: klpp_map_key_clear(KEY_OPEN);		break;
		case 0x203: klpp_map_key_clear(KEY_CLOSE);		break;
		case 0x204: klpp_map_key_clear(KEY_EXIT);		break;
		case 0x207: klpp_map_key_clear(KEY_SAVE);		break;
		case 0x208: klpp_map_key_clear(KEY_PRINT);		break;
		case 0x209: klpp_map_key_clear(KEY_PROPS);		break;
		case 0x21a: klpp_map_key_clear(KEY_UNDO);		break;
		case 0x21b: klpp_map_key_clear(KEY_COPY);		break;
		case 0x21c: klpp_map_key_clear(KEY_CUT);		break;
		case 0x21d: klpp_map_key_clear(KEY_PASTE);		break;
		case 0x21f: klpp_map_key_clear(KEY_FIND);		break;
		case 0x221: klpp_map_key_clear(KEY_SEARCH);		break;
		case 0x222: klpp_map_key_clear(KEY_GOTO);		break;
		case 0x223: klpp_map_key_clear(KEY_HOMEPAGE);	break;
		case 0x224: klpp_map_key_clear(KEY_BACK);		break;
		case 0x225: klpp_map_key_clear(KEY_FORWARD);		break;
		case 0x226: klpp_map_key_clear(KEY_STOP);		break;
		case 0x227: klpp_map_key_clear(KEY_REFRESH);		break;
		case 0x22a: klpp_map_key_clear(KEY_BOOKMARKS);	break;
		case 0x22d: klpp_map_key_clear(KEY_ZOOMIN);		break;
		case 0x22e: klpp_map_key_clear(KEY_ZOOMOUT);		break;
		case 0x22f: klpp_map_key_clear(KEY_ZOOMRESET);	break;
		case 0x232: klpp_map_key_clear(KEY_FULL_SCREEN);	break;
		case 0x233: klpp_map_key_clear(KEY_SCROLLUP);	break;
		case 0x234: klpp_map_key_clear(KEY_SCROLLDOWN);	break;
		case 0x238: /* AC Pan */
			set_bit(REL_HWHEEL, input->relbit);
			klpp_map_rel(REL_HWHEEL_HI_RES);
			break;
		case 0x23d: klpp_map_key_clear(KEY_EDIT);		break;
		case 0x25f: klpp_map_key_clear(KEY_CANCEL);		break;
		case 0x269: klpp_map_key_clear(KEY_INSERT);		break;
		case 0x26a: klpp_map_key_clear(KEY_DELETE);		break;
		case 0x279: klpp_map_key_clear(KEY_REDO);		break;

		case 0x289: klpp_map_key_clear(KEY_REPLY);		break;
		case 0x28b: klpp_map_key_clear(KEY_FORWARDMAIL);	break;
		case 0x28c: klpp_map_key_clear(KEY_SEND);		break;

		case 0x29d: klpp_map_key_clear(KEY_KBD_LAYOUT_NEXT);	break;

		case 0x2c7: klpp_map_key_clear(KEY_KBDINPUTASSIST_PREV);		break;
		case 0x2c8: klpp_map_key_clear(KEY_KBDINPUTASSIST_NEXT);		break;
		case 0x2c9: klpp_map_key_clear(KEY_KBDINPUTASSIST_PREVGROUP);		break;
		case 0x2ca: klpp_map_key_clear(KEY_KBDINPUTASSIST_NEXTGROUP);		break;
		case 0x2cb: klpp_map_key_clear(KEY_KBDINPUTASSIST_ACCEPT);	break;
		case 0x2cc: klpp_map_key_clear(KEY_KBDINPUTASSIST_CANCEL);	break;

		case 0x29f: klpp_map_key_clear(KEY_SCALE);		break;

		default: klpp_map_key_clear(KEY_UNKNOWN);
		}
		break;

	case HID_UP_GENDEVCTRLS:
		switch (usage->hid) {
		case HID_DC_BATTERYSTRENGTH:
			klpr_hidinput_setup_battery(device, HID_INPUT_REPORT, field);
			usage->type = EV_PWR;
			goto ignore;
		}
		goto unknown;

	case HID_UP_HPVENDOR:	/* Reported on a Dutch layout HP5308 */
		set_bit(EV_REP, input->evbit);
		switch (usage->hid & HID_USAGE) {
		case 0x021: klpp_map_key_clear(KEY_PRINT);           break;
		case 0x070: klpp_map_key_clear(KEY_HP);		break;
		case 0x071: klpp_map_key_clear(KEY_CAMERA);		break;
		case 0x072: klpp_map_key_clear(KEY_SOUND);		break;
		case 0x073: klpp_map_key_clear(KEY_QUESTION);	break;
		case 0x080: klpp_map_key_clear(KEY_EMAIL);		break;
		case 0x081: klpp_map_key_clear(KEY_CHAT);		break;
		case 0x082: klpp_map_key_clear(KEY_SEARCH);		break;
		case 0x083: klpp_map_key_clear(KEY_CONNECT);	        break;
		case 0x084: klpp_map_key_clear(KEY_FINANCE);		break;
		case 0x085: klpp_map_key_clear(KEY_SPORT);		break;
		case 0x086: klpp_map_key_clear(KEY_SHOP);	        break;
		default:    goto ignore;
		}
		break;

	case HID_UP_HPVENDOR2:
		set_bit(EV_REP, input->evbit);
		switch (usage->hid & HID_USAGE) {
		case 0x001: klpp_map_key_clear(KEY_MICMUTE);		break;
		case 0x003: klpp_map_key_clear(KEY_BRIGHTNESSDOWN);	break;
		case 0x004: klpp_map_key_clear(KEY_BRIGHTNESSUP);	break;
		default:    goto ignore;
		}
		break;

	case HID_UP_MSVENDOR:
		goto ignore;

	case HID_UP_CUSTOM: /* Reported on Logitech and Apple USB keyboards */
		set_bit(EV_REP, input->evbit);
		goto ignore;

	case HID_UP_LOGIVENDOR:
		/* intentional fallback */
	case HID_UP_LOGIVENDOR2:
		/* intentional fallback */
	case HID_UP_LOGIVENDOR3:
		goto ignore;

	case HID_UP_PID:
		switch (usage->hid & HID_USAGE) {
		case 0xa4: klpp_map_key_clear(BTN_DEAD);	break;
		default: goto ignore;
		}
		break;

	default:
	unknown:
		if (field->report_size == 1) {
			if (field->report->type == HID_OUTPUT_REPORT) {
				klpp_map_led(LED_MISC);
				break;
			}
			klpp_map_key(BTN_MISC);
			break;
		}
		if (field->flags & HID_MAIN_ITEM_RELATIVE) {
			klpp_map_rel(REL_MISC);
			break;
		}
		klpp_map_abs(ABS_MISC);
		break;
	}

mapped:
	/*
	 * Fix CVE-2020-0465
	 *  +3 lines
	 */
	/* Mapping failed, bail out */
	if (!bit)
		return;

	if (device->driver->input_mapped &&
	    device->driver->input_mapped(device, hidinput, field, usage,
					 &bit, &max) < 0) {
		/*
		 * The driver indicated that no further generic handling
		 * of the usage is desired.
		 */
		return;
	}

	set_bit(usage->type, input->evbit);

	/*
	 * This part is *really* controversial:
	 * - HID aims at being generic so we should do our best to export
	 *   all incoming events
	 * - HID describes what events are, so there is no reason for ABS_X
	 *   to be mapped to ABS_Y
	 * - HID is using *_MISC+N as a default value, but nothing prevents
	 *   *_MISC+N to overwrite a legitimate even, which confuses userspace
	 *   (for instance ABS_MISC + 7 is ABS_MT_SLOT, which has a different
	 *   processing)
	 *
	 * If devices still want to use this (at their own risk), they will
	 * have to use the quirk HID_QUIRK_INCREMENT_USAGE_ON_DUPLICATE, but
	 * the default should be a reliable mapping.
	 */
	while (usage->code <= max && test_and_set_bit(usage->code, bit)) {
		if (device->quirks & HID_QUIRK_INCREMENT_USAGE_ON_DUPLICATE) {
			usage->code = find_next_zero_bit(bit,
							 max + 1,
							 usage->code);
		} else {
			device->status |= HID_STAT_DUP_DETECTED;
			goto ignore;
		}
	}

	if (usage->code > max)
		goto ignore;

	if (usage->type == EV_ABS) {

		int a = field->logical_minimum;
		int b = field->logical_maximum;

		if ((device->quirks & HID_QUIRK_BADPAD) && (usage->code == ABS_X || usage->code == ABS_Y)) {
			a = field->logical_minimum = 0;
			b = field->logical_maximum = 255;
		}

		if (field->application == HID_GD_GAMEPAD || field->application == HID_GD_JOYSTICK)
			input_set_abs_params(input, usage->code, a, b, (b - a) >> 8, (b - a) >> 4);
		else	input_set_abs_params(input, usage->code, a, b, 0, 0);

		input_abs_set_res(input, usage->code,
				  hidinput_calc_abs_res(field, usage->code));

		/* use a larger default input buffer for MT devices */
		if (usage->code == ABS_MT_POSITION_X && input->hint_events_per_packet == 0)
			input_set_events_per_packet(input, 60);
	}

	if (usage->type == EV_ABS &&
	    (usage->hat_min < usage->hat_max || usage->hat_dir)) {
		int i;
		for (i = usage->code; i < usage->code + 2 && i <= max; i++) {
			input_set_abs_params(input, i, -1, 1, 0, 0);
			set_bit(i, input->absbit);
		}
		if (usage->hat_dir && !field->dpad)
			field->dpad = usage->code;
	}

	/* for those devices which produce Consumer volume usage as relative,
	 * we emulate pressing volumeup/volumedown appropriate number of times
	 * in hidinput_hid_event()
	 */
	if ((usage->type == EV_ABS) && (field->flags & HID_MAIN_ITEM_RELATIVE) &&
			(usage->code == ABS_VOLUME)) {
		set_bit(KEY_VOLUMEUP, input->keybit);
		set_bit(KEY_VOLUMEDOWN, input->keybit);
	}

	if (usage->type == EV_KEY) {
		set_bit(EV_MSC, input->evbit);
		set_bit(MSC_SCAN, input->mscbit);
	}

	return;

ignore:
	usage->type = 0;
	usage->code = 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1180030.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "hid_keyboard", (void *)&klpe_hid_keyboard },
#ifdef CONFIG_HID_BATTERY_STRENGTH
	{ "hidinput_setup_battery", (void *)&klpe_hidinput_setup_battery },
#endif
};

int livepatch_bsc1180030_hid_input_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_HID) */
