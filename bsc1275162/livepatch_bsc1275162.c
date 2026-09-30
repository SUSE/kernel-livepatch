/*
 * livepatch_bsc1275162
 *
 * Fix for CVE-2026-68202, bsc#1275162
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_SND_SEQUENCER)

#if !IS_MODULE(CONFIG_SND_SEQUENCER)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1275162.h"


/* klp-ccp: from sound/core/seq/seq_timer.c */
#include <sound/core.h>
#include <linux/slab.h>
/* klp-ccp: from sound/core/seq/seq_timer.h */
#include <sound/timer.h>
#include <sound/seq_kernel.h>

struct snd_seq_timer_tick {
	snd_seq_tick_time_t	cur_tick;	/* current tick */
	unsigned long		resolution;	/* time per tick in nsec */
	unsigned long		fraction;	/* current time per tick in nsec */
};

struct snd_seq_timer {
	/* ... tempo / offset / running state */

	unsigned int		running:1,	/* running state of queue */	
				initialized:1;	/* timer is initialized */

	unsigned int		tempo;		/* current tempo, us/tick */
	int			ppq;		/* time resolution, ticks/quarter */

	snd_seq_real_time_t	cur_time;	/* current time */
	struct snd_seq_timer_tick	tick;	/* current tick */
	int tick_updated;
	
	int			type;		/* timer type */
	struct snd_timer_id	alsa_id;	/* ALSA's timer ID */
	struct snd_timer_instance	*timeri;	/* timer instance */
	unsigned int		ticks;
	unsigned long		preferred_resolution; /* timer resolution, ticks/sec */

	unsigned int skew;
	unsigned int skew_base;
	unsigned int tempo_base;

	struct timespec64	last_update;	 /* time of last clock update, used for interpolation */

	spinlock_t lock;
};
void snd_seq_timer_reset(struct snd_seq_timer *tmr);
int snd_seq_timer_stop(struct snd_seq_timer *tmr);

/* klp-ccp: from sound/core/seq/seq_memory.h */
#include <sound/seq_kernel.h>
#include <linux/poll.h>
/* klp-ccp: from sound/core/seq/seq_lock.h */
#include <linux/sched.h>
/* klp-ccp: from sound/core/seq/seq_queue.h */
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/bitops.h>
/* klp-ccp: from sound/core/seq/seq_info.h */
#include <sound/info.h>
#include <sound/seq_kernel.h>

/* klp-ccp: from sound/core/seq/seq_timer.c */
void klpp_snd_seq_timer_delete(struct snd_seq_timer **tmr)
{
	struct snd_seq_timer *t = *tmr;
	struct snd_timer_instance *ti;

	if (t == NULL) {
		pr_debug("ALSA: seq: snd_seq_timer_delete() called with NULL timer\n");
		return;
	}

	scoped_guard(spinlock_irq, &t->lock) {
		ti = t->timeri;
		t->timeri = NULL;
	}
	if (ti) {
		snd_timer_close(ti);
		snd_timer_instance_free(ti);
	}

	*tmr = NULL;
	t->running = 0;

	/* reset time */
	snd_seq_timer_stop(t);
	snd_seq_timer_reset(t);

	kfree(t);
}

void snd_seq_timer_reset(struct snd_seq_timer *tmr);

int snd_seq_timer_stop(struct snd_seq_timer *tmr);


#include <linux/livepatch.h>

extern typeof(snd_seq_timer_reset) snd_seq_timer_reset
	 KLP_RELOC_SYMBOL(snd_seq, snd_seq, snd_seq_timer_reset);
extern typeof(snd_seq_timer_stop) snd_seq_timer_stop
	 KLP_RELOC_SYMBOL(snd_seq, snd_seq, snd_seq_timer_stop);
extern typeof(snd_timer_close) snd_timer_close
	 KLP_RELOC_SYMBOL(snd_seq, snd_timer, snd_timer_close);
extern typeof(snd_timer_instance_free) snd_timer_instance_free
	 KLP_RELOC_SYMBOL(snd_seq, snd_timer, snd_timer_instance_free);

#endif /* IS_ENABLED(CONFIG_SND_SEQUENCER) */
