/*
 * livepatch_bsc1197597
 *
 * Fix for CVE-2022-1048, bsc#1197597
 *
 *  Upstream commits:
 *  92ee3c60ec9f ("ALSA: pcm: Fix races among concurrent hw_params and hw_free
 *                 calls")
 *  dca947d4d26d ("ALSA: pcm: Fix races among concurrent read/write and buffer
 *                 changes")
 *  3c3201f8c7bb ("ALSA: pcm: Fix races among concurrent prepare and
 *                 hw_params/hw_free")
 *  69534c48ba8c ("ALSA: pcm: Fix races among concurrent prealloc proc writes")
 *  bc55cfd5718c ("ALSA: pcm: Fix potential AB/BA lock with buffer_mutex and
 *                 mmap_lock")
 *
 *  SLE12-SP3 commits:
 *  393637131c012f42a33ebcda43e5ebd0a69e6573
 *  5136d1b69d80d88ddce38bb682cf86ae318d2dba
 *  abaefc5d9011ec1057518ab9093741b98826f311
 *  38cc86f2c89358b8729411b1db0e5af195c4b010
 *  2d921d0d15c9190c7fa2486e0932744703302eb6
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  2de41ab68c7b84284abac5e49762acc321fc3418
 *  c5698609b0b48bed0c07c5950a3768c26988a612
 *  eed910d5d64c56a7e77b0e5527f7750bf5984198
 *  0f72275eed3fa79db317a2c38f41bb3cdd88b17d
 *  62bc95010ccc65aa567818f6df3d2fefc9eaf0b0
 *
 *  SLE15-SP2 and -SP3 commits:
 *  b71ba27f5d54ff8cb241f68aebab011f4ba0dde1
 *  fa7213a2471dadabe7a9b299f0ad4feb92450002
 *  a4f7393c1e83217245d89e797b554aaa52f4edae
 *  aee063fa034ed9dc146985658aa8663a0d395efa
 *  db7647d32a24e4b3ff04b0896c769d876b4fe2d7
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#if IS_ENABLED(CONFIG_SND_PCM)

#if !IS_MODULE(CONFIG_SND_PCM)
#error "Live patch supports only CONFIG=m"
#endif

#include <linux/mutex.h>
#include "../shadow.h"

#define KLP_BSC1197597_SHARED_STATE_ID KLP_SHADOW_ID(1197597, 0)
#define KLP_BSC1197597_BUFFER_ACESSING_ID KLP_SHADOW_ID(1197597, 1)

#include "livepatch_bsc1197597.h"

struct klp_bsc1197597_shared_state *klp_bsc1197597_shared_state;

#include <linux/livepatch.h>

static int klp_bsc1197597_init_shared_state(void *obj,
					void *shadow_data,
					void *ctor_data)
{
	struct klp_bsc1197597_shared_state *s = shadow_data;

	memset(s, 0, sizeof(*s));
	mutex_init(&s->snd_pcm_runtime_buffer_mutex);
	spin_lock_init(&s->spin);

	return 0;
}

static void klp_bsc1197597_destroy_shared_state(void *obj,
					void *shadow_data)
{
	struct klp_bsc1197597_shared_state *s = shadow_data;

	mutex_destroy(&s->snd_pcm_runtime_buffer_mutex);
}

/* Must be called with module_mutex held. */
static int klp_bsc1197597_get_shared_state(void)
{
	klp_bsc1197597_shared_state =
		klp_shadow_get_or_alloc(NULL, KLP_BSC1197597_SHARED_STATE_ID,
				sizeof(*klp_bsc1197597_shared_state),
				GFP_KERNEL,
				klp_bsc1197597_init_shared_state, NULL);
	if (!klp_bsc1197597_shared_state)
		return -ENOMEM;

	++klp_bsc1197597_shared_state->refcount;

	return 0;
}

/* Must be called with module_mutex held. */
static void klp_bsc1197597_put_shared_state(void)
{
	--klp_bsc1197597_shared_state->refcount;
	if (!klp_bsc1197597_shared_state->refcount) {
		klp_shadow_free(NULL, KLP_BSC1197597_SHARED_STATE_ID,
				klp_bsc1197597_destroy_shared_state);
	}

	klp_bsc1197597_shared_state = NULL;
}

int *klpp_runtime_get_buffer_accessing(struct snd_pcm_runtime *runtime)
{
	return klp_shadow_get_or_alloc(runtime,
					KLP_BSC1197597_BUFFER_ACESSING_ID,
					sizeof(int), GFP_ATOMIC, NULL, NULL);
}

void klpp_runtime_free_buffer_acessing(struct snd_pcm_runtime *runtime)
{
	klp_shadow_free(runtime, KLP_BSC1197597_BUFFER_ACESSING_ID, NULL);
}

int livepatch_bsc1197597_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	ret = klp_bsc1197597_get_shared_state();
	mutex_unlock(&module_mutex);

	if (ret)
		return ret;

	ret = bsc1197597_pcm_native_init();
	if (ret)
		goto err;

	ret = bsc1197597_pcm_lib_init();
	if (ret)
		goto out_native;

	ret = bsc1197597_pcm_memory_init();
	if (ret)
		goto out_lib;

	return 0;

out_lib:
	bsc1197597_pcm_lib_cleanup();
out_native:
	bsc1197597_pcm_native_cleanup();
err:
	mutex_lock(&module_mutex);
	klp_bsc1197597_put_shared_state();
	mutex_unlock(&module_mutex);

	return ret;
}

void livepatch_bsc1197597_cleanup(void)
{
	bsc1197597_pcm_memory_cleanup();
	bsc1197597_pcm_lib_cleanup();
	bsc1197597_pcm_native_cleanup();

	mutex_lock(&module_mutex);
	klp_bsc1197597_put_shared_state();
	mutex_unlock(&module_mutex);
}

#endif /* IS_ENABLED(CONFIG_SND_PCM) */
