#ifndef _BSC1192036_H_
#define _BSC1192036_H_

int livepatch_bsc1192036_firewire_firedtv_avc_init(void);
void livepatch_bsc1192036_firewire_firedtv_avc_cleanup(void);

int livepatch_bsc1192036_firewire_firedtv_ci_init(void);
void livepatch_bsc1192036_firewire_firedtv_ci_cleanup(void);

#include <linux/device.h>

/* klp-ccp: from drivers/media/dvb-core/dvb_frontend.h */
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ioctl.h>

/* klp-ccp: from drivers/media/dvb-core/dvb_frontend.h */
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/mutex.h>

/* klp-ccp: from drivers/media/dvb-core/dvb_frontend.h */
#include <linux/dvb/frontend.h>
/* klp-ccp: from drivers/media/dvb-core/dvbdev.h */
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/list.h>

struct dvb_frontend;

struct dvb_adapter {
	int num;
	struct list_head list_head;
	struct list_head device_list;
	const char *name;
	u8 proposed_mac [6];
	void* priv;

	struct device *device;

	struct module *module;

	int mfe_shared;			/* indicates mutually exclusive frontends */
	struct dvb_device *mfe_dvbdev;	/* frontend device in use */
	struct mutex mfe_lock;		/* access lock for thread creation */

#if defined(CONFIG_MEDIA_CONTROLLER_DVB)
#error "klp-ccp: non-taken branch"
#endif
};

/* klp-ccp: from drivers/media/dvb-core/dvb_frontend.h */
#define MAX_DELSYS	8

struct dvb_frontend_tune_settings;

struct dvb_tuner_info {
	char name[128];

	u32 frequency_min;
	u32 frequency_max;
	u32 frequency_step;

	u32 bandwidth_min;
	u32 bandwidth_max;
	u32 bandwidth_step;
};

struct analog_parameters;

struct dvb_tuner_ops {

	struct dvb_tuner_info info;

	void (*release)(struct dvb_frontend *fe);
	int (*init)(struct dvb_frontend *fe);
	int (*sleep)(struct dvb_frontend *fe);
	int (*suspend)(struct dvb_frontend *fe);
	int (*resume)(struct dvb_frontend *fe);

	/* This is the recomended way to set the tuner */
	int (*set_params)(struct dvb_frontend *fe);
	int (*set_analog_params)(struct dvb_frontend *fe, struct analog_parameters *p);

	int (*set_config)(struct dvb_frontend *fe, void *priv_cfg);

	int (*get_frequency)(struct dvb_frontend *fe, u32 *frequency);
	int (*get_bandwidth)(struct dvb_frontend *fe, u32 *bandwidth);
	int (*get_if_frequency)(struct dvb_frontend *fe, u32 *frequency);

	int (*get_status)(struct dvb_frontend *fe, u32 *status);
	int (*get_rf_strength)(struct dvb_frontend *fe, u16 *strength);
	int (*get_afc)(struct dvb_frontend *fe, s32 *afc);

	/*
	 * This is support for demods like the mt352 - fills out the supplied
	 * buffer with what to write.
	 *
	 * Don't use on newer drivers.
	 */
	int (*calc_regs)(struct dvb_frontend *fe, u8 *buf, int buf_len);

	/*
	 * These are provided separately from set_params in order to
	 * facilitate silicon tuners which require sophisticated tuning loops,
	 * controlling each parameter separately.
	 *
	 * Don't use on newer drivers.
	 */
	int (*set_frequency)(struct dvb_frontend *fe, u32 frequency);
	int (*set_bandwidth)(struct dvb_frontend *fe, u32 bandwidth);
};

struct analog_demod_info {
	char *name;
};

struct analog_demod_ops {

	struct analog_demod_info info;

	void (*set_params)(struct dvb_frontend *fe,
			   struct analog_parameters *params);
	int  (*has_signal)(struct dvb_frontend *fe, u16 *signal);
	int  (*get_afc)(struct dvb_frontend *fe, s32 *afc);
	void (*tuner_status)(struct dvb_frontend *fe);
	void (*standby)(struct dvb_frontend *fe);
	void (*release)(struct dvb_frontend *fe);
	int  (*i2c_gate_ctrl)(struct dvb_frontend *fe, int enable);

	/** This is to allow setting tuner-specific configuration */
	int (*set_config)(struct dvb_frontend *fe, void *priv_cfg);
};

struct dtv_frontend_properties;

struct dvb_frontend_ops {

	struct dvb_frontend_info info;

	u8 delsys[MAX_DELSYS];

	void (*detach)(struct dvb_frontend *fe);
	void (*release)(struct dvb_frontend* fe);
	void (*release_sec)(struct dvb_frontend* fe);

	int (*init)(struct dvb_frontend* fe);
	int (*sleep)(struct dvb_frontend* fe);

	int (*write)(struct dvb_frontend* fe, const u8 buf[], int len);

	/* if this is set, it overrides the default swzigzag */
	int (*tune)(struct dvb_frontend* fe,
		    bool re_tune,
		    unsigned int mode_flags,
		    unsigned int *delay,
		    enum fe_status *status);

	/* get frontend tuning algorithm from the module */
	enum dvbfe_algo (*get_frontend_algo)(struct dvb_frontend *fe);

	/* these two are only used for the swzigzag code */
	int (*set_frontend)(struct dvb_frontend *fe);
	int (*get_tune_settings)(struct dvb_frontend* fe, struct dvb_frontend_tune_settings* settings);

	int (*get_frontend)(struct dvb_frontend *fe,
			    struct dtv_frontend_properties *props);

	int (*read_status)(struct dvb_frontend *fe, enum fe_status *status);
	int (*read_ber)(struct dvb_frontend* fe, u32* ber);
	int (*read_signal_strength)(struct dvb_frontend* fe, u16* strength);
	int (*read_snr)(struct dvb_frontend* fe, u16* snr);
	int (*read_ucblocks)(struct dvb_frontend* fe, u32* ucblocks);

	int (*diseqc_reset_overload)(struct dvb_frontend* fe);
	int (*diseqc_send_master_cmd)(struct dvb_frontend* fe, struct dvb_diseqc_master_cmd* cmd);
	int (*diseqc_recv_slave_reply)(struct dvb_frontend* fe, struct dvb_diseqc_slave_reply* reply);
	int (*diseqc_send_burst)(struct dvb_frontend *fe,
				 enum fe_sec_mini_cmd minicmd);
	int (*set_tone)(struct dvb_frontend *fe, enum fe_sec_tone_mode tone);
	int (*set_voltage)(struct dvb_frontend *fe,
			   enum fe_sec_voltage voltage);
	int (*enable_high_lnb_voltage)(struct dvb_frontend* fe, long arg);
	int (*dishnetwork_send_legacy_command)(struct dvb_frontend* fe, unsigned long cmd);
	int (*i2c_gate_ctrl)(struct dvb_frontend* fe, int enable);
	int (*ts_bus_ctrl)(struct dvb_frontend* fe, int acquire);
	int (*set_lna)(struct dvb_frontend *);

	/*
	 * These callbacks are for devices that implement their own
	 * tuning algorithms, rather than a simple swzigzag
	 */
	enum dvbfe_search (*search)(struct dvb_frontend *fe);

	struct dvb_tuner_ops tuner_ops;
	struct analog_demod_ops analog_ops;

	int (*set_property)(struct dvb_frontend* fe, struct dtv_property* tvp);
	int (*get_property)(struct dvb_frontend* fe, struct dtv_property* tvp);
};

struct dtv_frontend_properties {
	u32			frequency;
	enum fe_modulation	modulation;

	enum fe_sec_voltage	voltage;
	enum fe_sec_tone_mode	sectone;
	enum fe_spectral_inversion	inversion;
	enum fe_code_rate		fec_inner;
	enum fe_transmit_mode	transmission_mode;
	u32			bandwidth_hz;	/* 0 = AUTO */
	enum fe_guard_interval	guard_interval;
	enum fe_hierarchy		hierarchy;
	u32			symbol_rate;
	enum fe_code_rate		code_rate_HP;
	enum fe_code_rate		code_rate_LP;

	enum fe_pilot		pilot;
	enum fe_rolloff		rolloff;

	enum fe_delivery_system	delivery_system;

	enum fe_interleaving	interleaving;

	/* ISDB-T specifics */
	u8			isdbt_partial_reception;
	u8			isdbt_sb_mode;
	u8			isdbt_sb_subchannel;
	u32			isdbt_sb_segment_idx;
	u32			isdbt_sb_segment_count;
	u8			isdbt_layer_enabled;
	struct {
	    u8			segment_count;
	    enum fe_code_rate	fec;
	    enum fe_modulation	modulation;
	    u8			interleaving;
	} layer[3];

	/* Multistream specifics */
	u32			stream_id;

	/* ATSC-MH specifics */
	u8			atscmh_fic_ver;
	u8			atscmh_parade_id;
	u8			atscmh_nog;
	u8			atscmh_tnog;
	u8			atscmh_sgn;
	u8			atscmh_prc;

	u8			atscmh_rs_frame_mode;
	u8			atscmh_rs_frame_ensemble;
	u8			atscmh_rs_code_mode_pri;
	u8			atscmh_rs_code_mode_sec;
	u8			atscmh_sccc_block_mode;
	u8			atscmh_sccc_code_mode_a;
	u8			atscmh_sccc_code_mode_b;
	u8			atscmh_sccc_code_mode_c;
	u8			atscmh_sccc_code_mode_d;

	u32			lna;

	/* statistics data */
	struct dtv_fe_stats	strength;
	struct dtv_fe_stats	cnr;
	struct dtv_fe_stats	pre_bit_error;
	struct dtv_fe_stats	pre_bit_count;
	struct dtv_fe_stats	post_bit_error;
	struct dtv_fe_stats	post_bit_count;
	struct dtv_fe_stats	block_error;
	struct dtv_fe_stats	block_count;

	/* private: */
	/* Cache State */
	u32			state;

};

struct dvb_frontend {
	struct kref refcount;
	struct dvb_frontend_ops ops;
	struct dvb_adapter *dvb;
	void *demodulator_priv;
	void *tuner_priv;
	void *frontend_priv;
	void *sec_priv;
	void *analog_demod_priv;
	struct dtv_frontend_properties dtv_property_cache;
	int (*callback)(void *adapter_priv, int component, int cmd, int arg);
	int id;
	unsigned int exit;
};

/* klp-ccp: from drivers/media/firewire/firedtv.h */
#include <linux/time.h>
#include <linux/dvb/dmx.h>
#include <linux/dvb/frontend.h>
#include <linux/list.h>
#include <linux/mod_devicetable.h>
#include <linux/mutex.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
/* klp-ccp: from drivers/media/dvb-core/demux.h */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/dvb/dmx.h>

struct dmx_ts_feed;

struct dmx_section_filter;

struct dmx_section_feed;

typedef int (*dmx_ts_cb)(const u8 *buffer1,
			 size_t buffer1_length,
			 const u8 *buffer2,
			 size_t buffer2_length,
			 struct dmx_ts_feed *source);

typedef int (*dmx_section_cb)(const u8 *buffer1,
			      size_t buffer1_len,
			      const u8 *buffer2,
			      size_t buffer2_len,
			      struct dmx_section_filter *source);

enum dmx_frontend_source {
	DMX_MEMORY_FE,
	DMX_FRONTEND_0,
};

struct dmx_frontend {
	struct list_head connectivity_list;
	enum dmx_frontend_source source;
};

enum dmx_demux_caps {
	DMX_TS_FILTERING = 1,
	DMX_SECTION_FILTERING = 4,
	DMX_MEMORY_BASED_FILTERING = 8,
};

struct dmx_demux {
	enum dmx_demux_caps capabilities;
	struct dmx_frontend *frontend;
	void *priv;
	int (*open)(struct dmx_demux *demux);
	int (*close)(struct dmx_demux *demux);
	int (*write)(struct dmx_demux *demux, const char __user *buf,
		     size_t count);
	int (*allocate_ts_feed)(struct dmx_demux *demux,
				struct dmx_ts_feed **feed,
				dmx_ts_cb callback);
	int (*release_ts_feed)(struct dmx_demux *demux,
			       struct dmx_ts_feed *feed);
	int (*allocate_section_feed)(struct dmx_demux *demux,
				     struct dmx_section_feed **feed,
				     dmx_section_cb callback);
	int (*release_section_feed)(struct dmx_demux *demux,
				    struct dmx_section_feed *feed);
	int (*add_frontend)(struct dmx_demux *demux,
			    struct dmx_frontend *frontend);
	int (*remove_frontend)(struct dmx_demux *demux,
			       struct dmx_frontend *frontend);
	struct list_head *(*get_frontends)(struct dmx_demux *demux);
	int (*connect_frontend)(struct dmx_demux *demux,
				struct dmx_frontend *frontend);
	int (*disconnect_frontend)(struct dmx_demux *demux);

	int (*get_pes_pids)(struct dmx_demux *demux, u16 *pids);

	/* private: */

	/*
	 * Only used at av7110, to read some data from firmware.
	 * As this was never documented, we have no clue about what's
	 * there, and its usage on other drivers aren't encouraged.
	 */
	int (*get_stc)(struct dmx_demux *demux, unsigned int num,
		       u64 *stc, unsigned int *base);
};

/* klp-ccp: from drivers/media/dvb-core/dmxdev.h */
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/dvb/dmx.h>
/* klp-ccp: from drivers/media/dvb-core/dvb_ringbuffer.h */
#include <linux/spinlock.h>
#include <linux/wait.h>

struct dvb_ringbuffer {
	u8               *data;
	ssize_t           size;
	ssize_t           pread;
	ssize_t           pwrite;
	int               error;

	wait_queue_head_t queue;
	spinlock_t        lock;
};

/* klp-ccp: from drivers/media/dvb-core/dmxdev.h */
struct dmxdev {
	struct dvb_device *dvbdev;
	struct dvb_device *dvr_dvbdev;

	struct dmxdev_filter *filter;
	struct dmx_demux *demux;

	int filternum;
	int capabilities;

	unsigned int exit:1;
	struct dmx_frontend *dvr_orig_fe;

	struct dvb_ringbuffer dvr_buffer;

	struct mutex mutex;
	spinlock_t lock;
};

/* klp-ccp: from drivers/media/dvb-core/dvb_demux.h */
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

struct dvb_demux_feed;

struct dvb_demux {
	struct dmx_demux dmx;
	void *priv;
	int filternum;
	int feednum;
	int (*start_feed)(struct dvb_demux_feed *feed);
	int (*stop_feed)(struct dvb_demux_feed *feed);
	int (*write_to_decoder)(struct dvb_demux_feed *feed,
				 const u8 *buf, size_t len);
	u32 (*check_crc32)(struct dvb_demux_feed *feed,
			    const u8 *buf, size_t len);
	void (*memcopy)(struct dvb_demux_feed *feed, u8 *dst,
			 const u8 *src, size_t len);

	int users;
	struct dvb_demux_filter *filter;
	struct dvb_demux_feed *feed;

	struct list_head frontend_list;

	struct dvb_demux_feed *pesfilter[DMX_PES_OTHER];
	u16 pids[DMX_PES_OTHER];
	int playing;
	int recording;

	struct list_head feed_list;
	u8 tsbuf[204];
	int tsbufp;

	struct mutex mutex;
	spinlock_t lock;

	uint8_t *cnt_storage; /* for TS continuity check */

	ktime_t speed_last_time; /* for TS speed check */
	uint32_t speed_pkts_cnt; /* for TS speed check */
};

/* klp-ccp: from drivers/media/dvb-core/dvb_net.h */
#include <linux/module.h>

/* klp-ccp: from drivers/media/dvb-core/dvb_net.h */
#include <linux/skbuff.h>

#define DVB_NET_DEVICES_MAX 10

#ifdef CONFIG_DVB_NET

struct dvb_net {
	struct dvb_device *dvbdev;
	struct net_device *device[DVB_NET_DEVICES_MAX];
	int state[DVB_NET_DEVICES_MAX];
	unsigned int exit:1;
	struct dmx_demux *demux;
	struct mutex ioctl_mutex;
};

#else
#error "klp-ccp: non-taken branch"
#endif /* ifdef CONFIG_DVB_NET */

/* klp-ccp: from drivers/media/firewire/firedtv.h */
enum model_type {
	FIREDTV_UNKNOWN = 0,
	FIREDTV_DVB_S   = 1,
	FIREDTV_DVB_C   = 2,
	FIREDTV_DVB_T   = 3,
	FIREDTV_DVB_S2  = 4,
};

struct firedtv {
	struct device *device;
	struct list_head list;

	struct dvb_adapter	adapter;
	struct dmxdev		dmxdev;
	struct dvb_demux	demux;
	struct dmx_frontend	frontend;
	struct dvb_net		dvbnet;
	struct dvb_frontend	fe;

	struct dvb_device	*cadev;
	int			ca_last_command;
	int			ca_time_interval;

	struct mutex		avc_mutex;
	wait_queue_head_t	avc_wait;
	bool			avc_reply_received;
	struct work_struct	remote_ctrl_work;
	struct input_dev	*remote_ctrl_dev;

	enum model_type		type;
	char			subunit;
	s8			isochannel;
	struct fdtv_ir_context	*ir_context;

	enum fe_sec_voltage	voltage;
	enum fe_sec_tone_mode	tone;

	struct mutex		demux_mutex;
	unsigned long		channel_active;
	u16			channel_pid[16];

	int			avc_data_length;
	u8			avc_data[512];
};

int klpp_avc_ca_pmt(struct firedtv *fdtv, char *msg, int length);

#endif /* _BSC1192036_H_ */
