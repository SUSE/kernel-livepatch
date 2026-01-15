/*
 * livepatch_bsc1249242
 *
 * Fix for CVE-2022-50233, bsc#1249242
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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



#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/bluetooth/mgmt.c */
#include <linux/module.h>
#include <asm/unaligned.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>
#include <net/bluetooth/hci_sock.h>
#include <net/bluetooth/l2cap.h>
#include <net/bluetooth/mgmt.h>
/* klp-ccp: from net/bluetooth/hci_request.h */
#include <asm/unaligned.h>

static inline u16 eir_append_data(u8 *eir, u16 eir_len, u8 type,
				  u8 *data, u8 data_len)
{
	eir[eir_len++] = sizeof(type) + data_len;
	eir[eir_len++] = type;
	memcpy(&eir[eir_len], data, data_len);
	eir_len += data_len;

	return eir_len;
}

static inline u16 eir_append_le16(u8 *eir, u16 eir_len, u8 type, u16 data)
{
	eir[eir_len++] = sizeof(type) + sizeof(data);
	eir[eir_len++] = type;
	put_unaligned_le16(data, &eir[eir_len]);
	eir_len += sizeof(data);

	return eir_len;
}

/* klp-ccp: from net/bluetooth/mgmt.c */
u16 klpp_append_eir_data_to_buf(struct hci_dev *hdev, u8 *eir)
{
	u16 eir_len = 0;
	size_t name_len;

	if (hci_dev_test_flag(hdev, HCI_BREDR_ENABLED))
		eir_len = eir_append_data(eir, eir_len, EIR_CLASS_OF_DEV,
					  hdev->dev_class, 3);

	if (hci_dev_test_flag(hdev, HCI_LE_ENABLED))
		eir_len = eir_append_le16(eir, eir_len, EIR_APPEARANCE,
					  hdev->appearance);

	name_len = strnlen(hdev->dev_name, sizeof(hdev->dev_name));
	eir_len = eir_append_data(eir, eir_len, EIR_NAME_COMPLETE,
				  hdev->dev_name, name_len);

	name_len = strnlen(hdev->short_name, sizeof(hdev->short_name));
	eir_len = eir_append_data(eir, eir_len, EIR_NAME_SHORT,
				  hdev->short_name, name_len);

	return eir_len;
}


#include "livepatch_bsc1249242.h"

