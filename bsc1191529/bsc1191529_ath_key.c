/*
 * bsc1191529_ath_key
 *
 * Fix for CVE-2020-3702, bsc#1191529 (drivers/net/wireless/ath/key.c part)
 *
 *  Copyright (c) 2022 SUSE
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

#if IS_ENABLED(CONFIG_ATH9K)

#if !IS_MODULE(CONFIG_ATH9K)
#error "Live patch supports only CONFIG_ATH9K=m"
#endif

#include "bsc1191529_common.h"

/* klp-ccp: from drivers/net/wireless/ath/key.c */
#include <linux/export.h>
#include <asm/unaligned.h>
#include <net/mac80211.h>
/* klp-ccp: from drivers/net/wireless/ath/ath.h */
static bool (*klpe_ath_hw_keyreset)(struct ath_common *common, u16 entry);
static bool (*klpe_ath_hw_keysetmac)(struct ath_common *common, u16 entry, const u8 *mac);

/* klp-ccp: from drivers/net/wireless/ath/key.c */
#define IEEE80211_WEP_NKID      4       /* number of key ids */

void klpp_ath_key_delete(struct ath_common *common, struct ieee80211_key_conf *key)
{
	/*
	 * Fix CVE-2020-3702
	 *  -1 line, +10 lines
	 */
	/* Leave CCMP and TKIP (main key) configured to avoid disabling
	 * encryption for potentially pending frames already in a TXQ with the
	 * keyix pointing to this key entry. Instead, only clear the MAC address
	 * to prevent RX processing from using this key cache entry.
	 */
	if (test_bit(key->hw_key_idx, common->ccmp_keymap) ||
	    test_bit(key->hw_key_idx, common->tkip_keymap))
		(*klpe_ath_hw_keysetmac)(common, key->hw_key_idx, NULL);
	else
		(*klpe_ath_hw_keyreset)(common, key->hw_key_idx);
	if (key->hw_key_idx < IEEE80211_WEP_NKID)
		return;

	clear_bit(key->hw_key_idx, common->keymap);
	clear_bit(key->hw_key_idx, common->ccmp_keymap);
	if (key->cipher != WLAN_CIPHER_SUITE_TKIP)
		return;

	clear_bit(key->hw_key_idx + 64, common->keymap);

	clear_bit(key->hw_key_idx, common->tkip_keymap);
	clear_bit(key->hw_key_idx + 64, common->tkip_keymap);

	if (!(common->crypt_caps & ATH_CRYPT_CAP_MIC_COMBINED)) {
		(*klpe_ath_hw_keyreset)(common, key->hw_key_idx + 32);
		clear_bit(key->hw_key_idx + 32, common->keymap);
		clear_bit(key->hw_key_idx + 64 + 32, common->keymap);

		clear_bit(key->hw_key_idx + 32, common->tkip_keymap);
		clear_bit(key->hw_key_idx + 64 + 32, common->tkip_keymap);
	}
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1191529.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "ath"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ath_hw_keyreset", (void *)&klpe_ath_hw_keyreset, "ath" },
	{ "ath_hw_keysetmac", (void *)&klpe_ath_hw_keysetmac, "ath" },
};

static int livepatch_bsc1191529_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1191529_module_nb = {
	.notifier_call = livepatch_bsc1191529_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1191529_ath_key_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1191529_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1191529_ath_key_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1191529_module_nb);
}

#endif /* IS_ENABLED(CONFIG_ATH9K) */
