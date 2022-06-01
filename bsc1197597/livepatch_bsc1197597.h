#ifndef _LIVEPATCH_BSC1197597_H
#define _LIVEPATCH_BSC1197597_H

#if IS_ENABLED(CONFIG_SND_PCM)

#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <sound/pcm.h>

/* Protected by module_mutex. */
struct klp_bsc1197597_shared_state {
	unsigned long refcount;
	struct mutex snd_pcm_runtime_buffer_mutex;
	spinlock_t spin;
};

struct action_ops;
struct snd_pcm_substream;

int klpp_snd_pcm_action_nonatomic(const struct action_ops *ops,
				    struct snd_pcm_substream *substream,
				    snd_pcm_state_t state);

struct snd_pcm_hw_params;

int klpp_snd_pcm_hw_params(struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *params);

struct file;

int klpp_snd_pcm_common_ioctl(struct file *file,
				 struct snd_pcm_substream *substream,
				 unsigned int cmd, void __user *arg);

struct snd_info_entry;
struct snd_info_buffer;

void klpp_snd_pcm_lib_preallocate_proc_write(struct snd_info_entry *entry,
					       struct snd_info_buffer *buffer);

snd_pcm_sframes_t klpp___snd_pcm_lib_xfer(struct snd_pcm_substream *substream,
				     void *data, bool interleaved,
				     snd_pcm_uframes_t size, bool in_kernel);

struct snd_pcm_runtime;

int *klpp_runtime_get_buffer_accessing(struct snd_pcm_runtime *runtime);
void klpp_runtime_free_buffer_acessing(struct snd_pcm_runtime *runtime);

int bsc1197597_pcm_native_init(void);
void bsc1197597_pcm_native_cleanup(void);

int bsc1197597_pcm_memory_init(void);
void bsc1197597_pcm_memory_cleanup(void);

int bsc1197597_pcm_lib_init(void);
void bsc1197597_pcm_lib_cleanup(void);

int livepatch_bsc1197597_init(void);
void livepatch_bsc1197597_cleanup(void);

#else /* !IS_ENABLED(CONFIG_SND_PCM) */

static inline int livepatch_bsc1197597_init(void) { return 0; }
static inline void livepatch_bsc1197597_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SND_PCM) */

#endif /* _LIVEPATCH_BSC1197597_H */
