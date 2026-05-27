/*
 * livepatch_bsc1264096
 *
 * Fix for bsc#1264096
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_X86)

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/cpufeature.h>
#include <linux/livepatch.h>

#include "../kallsyms_relocs.h"

/* Zen4 */
#define MSR_ZEN4_BP_CFG			0xc001102e
#define MSR_ZEN2_BP_CFG_BUG_FIX_BIT	33

static enum cpuhp_state bsc1264096_hp_state;
static bool require_cpuhp_state_cleanup = false;

extern int msr_set_bit(u32 msr, u8 bit);

static bool cpu_is_affected(struct cpuinfo_x86 *c)
{
	if (c->x86_vendor != X86_VENDOR_AMD)
		return false;

	if (cpu_has(c, X86_FEATURE_HYPERVISOR))
		return false;

	switch (c->x86) {
	case 0x17:
		switch (c->x86_model) {
		case 0x30 ... 0x4f:
		case 0x60 ... 0x7f:
		case 0x90 ... 0x91:
		case 0xa0 ... 0xaf:
			return true;
		}
	}

	return false;
}

static int (*klpe_msr_set_bit)(u32 msr, u8 bit);

/*
 * cpuhp online callback. Runs on the target CPU itself, once for every
 * already-online CPU at registration time and again whenever a CPU is brought
 * online later.
 */
static int bsc1264096_amd_zen2(unsigned int cpu)
{
	struct cpuinfo_x86 *c = this_cpu_ptr(&cpu_info);

	if (!cpu_is_affected(c))
		return 0;

	int ret = (*klpe_msr_set_bit)(MSR_ZEN4_BP_CFG, MSR_ZEN2_BP_CFG_BUG_FIX_BIT);

	if (ret < 0)
		pr_warn("bsc1264096: msr_set_bit(0x%x, %u) failed on CPU%u: %d\n",
			MSR_ZEN4_BP_CFG, MSR_ZEN2_BP_CFG_BUG_FIX_BIT, cpu, ret);
	else if (ret > 0)
		pr_debug("bsc1264096: bit set on CPU%u\n", cpu);

	/* ret == 0: bit was already set, nothing to do */
	return 0;   /* don't fail the hotplug transition */
}

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "msr_set_bit", (void *)&klpe_msr_set_bit },
};

int livepatch_bsc1264096_init(void){
	struct cpuinfo_x86 *c = &boot_cpu_data;
	int ret;

	/* Only check boot CPU */
	if (!cpu_is_affected(c)) {
		pr_info("bsc1264096: CPU not affected, skipping\n");
		return 0;
	}

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	if (ret) {
		pr_err("bsc1264096: kallsyms lookup failed: %d\n", ret);
		return ret;
	}

	/*
	 * No teardown callback: we deliberately leave the bit set on CPU
	 * offline and on livepatch unload.
	 */
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"bsc1264096:online",
				bsc1264096_amd_zen2,
				NULL);
	if (ret < 0) {
		pr_err("bsc1264096: cpuhp_setup_state failed: %d\n", ret);
		return ret;
	}

	bsc1264096_hp_state = ret;
	require_cpuhp_state_cleanup = true;
	pr_info("bsc1264096: loaded\n");

	return 0;
}

void livepatch_bsc1264096_cleanup(void){
	if (require_cpuhp_state_cleanup) {
		/*
		 * Still required even though there is no teardown callback:
		 * deregisters the state slot so the framework won't invoke our
		 * (about-to-be-unloaded) startup callback on a future CPU online.
		 */
		cpuhp_remove_state(bsc1264096_hp_state);
	}
}

#endif /* IS_ENABLED(CONFIG_X86) */
