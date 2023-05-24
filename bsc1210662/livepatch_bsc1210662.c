/*
 * livepatch_bsc1210662
 *
 * Fix for CVE-2023-2162, bsc#1210662
 *
 *  Upstream commit:
 *  f484a794e4ee ("scsi: iscsi_tcp: Fix UAF during login when accessing the shost")
 *
 *  SLE12-SP4, SLE12-SP5 and SLE15-SP1 commit:
 *  eba27cda784aa838bb953dca65aad29e216e6482
 *
 *  SLE15-SP2 and -SP3 commit:
 *  d0a859e1cdd4e5349542fcf7bff3fff0822d4b2b
 *
 *  SLE15-SP4 commit:
 *  eef1aef01c12d1045e4ef473265cc8cfa2281e0b
 *
 *  Copyright (c) 2023 SUSE
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

/* klp-ccp: from drivers/scsi/iscsi_tcp.c */
#include <crypto/hash.h>
#include <linux/types.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/kfifo.h>
#include <linux/scatterlist.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi.h>
#include <scsi/scsi_transport_iscsi.h>
/* klp-ccp: from drivers/scsi/iscsi_tcp.h */
#include <scsi/libiscsi.h>

/* klp-ccp: from include/scsi/libiscsi.h */
static int (*klpe_iscsi_host_get_param)(struct Scsi_Host *shost,
				enum iscsi_host_param param, char *buf);
static int (*klpe_iscsi_host_add)(struct Scsi_Host *shost, struct device *pdev);
static struct Scsi_Host *(*klpe_iscsi_host_alloc)(struct scsi_host_template *sht,
					  int dd_data_size,
					  bool xmit_can_sleep);
static void (*klpe_iscsi_host_remove)(struct Scsi_Host *shost);
static void (*klpe_iscsi_host_free)(struct Scsi_Host *shost);

static struct iscsi_cls_session *
(*klpe_iscsi_session_setup)(struct iscsi_transport *, struct Scsi_Host *shost,
		    uint16_t, int, int, uint32_t, unsigned int);
static void (*klpe_iscsi_session_teardown)(struct iscsi_cls_session *);

static int (*klpe_iscsi_conn_get_addr_param)(struct sockaddr_storage *addr,
				     enum iscsi_param param, char *buf);

/* klp-ccp: from drivers/scsi/iscsi_tcp.h */
#include <scsi/libiscsi_tcp.h>

/* klp-ccp: from include/scsi/libiscsi_tcp.h */
static int (*klpe_iscsi_tcp_r2tpool_alloc)(struct iscsi_session *session);

/* klp-ccp: from drivers/scsi/iscsi_tcp.h */
struct iscsi_sw_tcp_send {
	struct iscsi_hdr	*hdr;
	struct iscsi_segment	segment;
	struct iscsi_segment	data_segment;
};

struct iscsi_sw_tcp_conn {
	struct socket		*sock;

	struct iscsi_sw_tcp_send out;
	/* old values for socket callbacks */
	void			(*old_data_ready)(struct sock *);
	void			(*old_state_change)(struct sock *);
	void			(*old_write_space)(struct sock *);

	/* data and header digests */
	struct ahash_request	*tx_hash;	/* CRC32C (Tx) */
	struct ahash_request	*rx_hash;	/* CRC32C (Rx) */

	/* MIB custom statistics */
	uint32_t		sendpage_failures_cnt;
	uint32_t		discontiguous_hdr_cnt;

	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
};

struct iscsi_sw_tcp_host {
	struct iscsi_session	*session;
};

struct iscsi_sw_tcp_hdrbuf {
	struct iscsi_hdr	hdrbuf;
	char			hdrextbuf[ISCSI_MAX_AHS_SIZE +
		                                  ISCSI_DIGEST_SIZE];
};

/* klp-ccp: from drivers/scsi/iscsi_tcp.c */
static struct scsi_transport_template *(*klpe_iscsi_sw_tcp_scsi_transport);
static struct scsi_host_template (*klpe_iscsi_sw_tcp_sht);
static struct iscsi_transport (*klpe_iscsi_sw_tcp_transport);

static unsigned int (*klpe_iscsi_max_lun);

int klpp_iscsi_sw_tcp_host_get_param(struct Scsi_Host *shost,
				       enum iscsi_host_param param, char *buf)
{
	struct iscsi_sw_tcp_host *tcp_sw_host = iscsi_host_priv(shost);
	struct iscsi_session *session;
	struct iscsi_conn *conn;
	struct iscsi_tcp_conn *tcp_conn;
	struct iscsi_sw_tcp_conn *tcp_sw_conn;
	struct sockaddr_in6 addr;
	struct socket *sock;
	int rc, len;

	switch (param) {
	case ISCSI_HOST_PARAM_IPADDRESS:
		session = tcp_sw_host->session;
		if (!session)
			return -ENOTCONN;

		spin_lock_bh(&session->frwd_lock);
		conn = session->leadconn;
		if (!conn) {
			spin_unlock_bh(&session->frwd_lock);
			return -ENOTCONN;
		}
		tcp_conn = conn->dd_data;
		tcp_sw_conn = tcp_conn->dd_data;
		sock = tcp_sw_conn->sock;
		if (!sock) {
			spin_unlock_bh(&session->frwd_lock);
			return -ENOTCONN;
		}
		sock_hold(sock->sk);
		spin_unlock_bh(&session->frwd_lock);

		rc = kernel_getsockname(sock,
					(struct sockaddr *)&addr, &len);
		sock_put(sock->sk);
		if (rc)
			return rc;

		return (*klpe_iscsi_conn_get_addr_param)((struct sockaddr_storage *)
						 &addr, param, buf);
	default:
		return (*klpe_iscsi_host_get_param)(shost, param, buf);
	}

	return 0;
}

struct iscsi_cls_session *
klpp_iscsi_sw_tcp_session_create(struct iscsi_endpoint *ep, uint16_t cmds_max,
			    uint16_t qdepth, uint32_t initial_cmdsn)
{
	struct iscsi_cls_session *cls_session;
	struct iscsi_session *session;
	struct iscsi_sw_tcp_host *tcp_sw_host;
	struct Scsi_Host *shost;

	if (ep) {
		printk(KERN_ERR "iscsi_tcp: invalid ep %p.\n", ep);
		return NULL;
	}

	shost = (*klpe_iscsi_host_alloc)(&(*klpe_iscsi_sw_tcp_sht),
				 sizeof(struct iscsi_sw_tcp_host), 1);
	if (!shost)
		return NULL;
	shost->transportt = (*klpe_iscsi_sw_tcp_scsi_transport);
	shost->cmd_per_lun = qdepth;
	shost->max_lun = (*klpe_iscsi_max_lun);
	shost->max_id = 0;
	shost->max_channel = 0;
	shost->max_cmd_len = SCSI_MAX_VARLEN_CDB_SIZE;

	if ((*klpe_iscsi_host_add)(shost, NULL))
		goto free_host;

	cls_session = (*klpe_iscsi_session_setup)(&(*klpe_iscsi_sw_tcp_transport), shost,
					  cmds_max, 0,
					  sizeof(struct iscsi_tcp_task) +
					  sizeof(struct iscsi_sw_tcp_hdrbuf),
					  initial_cmdsn, 0);
	if (!cls_session)
		goto remove_host;
	session = cls_session->dd_data;

	shost->can_queue = session->scsi_cmds_max;
	if ((*klpe_iscsi_tcp_r2tpool_alloc)(session))
		goto remove_session;

	/* We are now fully setup so expose the session to sysfs. */
	tcp_sw_host = iscsi_host_priv(shost);
	tcp_sw_host->session = session;
	return cls_session;

remove_session:
	(*klpe_iscsi_session_teardown)(cls_session);
remove_host:
	(*klpe_iscsi_host_remove)(shost);
free_host:
	(*klpe_iscsi_host_free)(shost);
	return NULL;
}



#define LP_MODULE "iscsi_tcp"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1210662.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "iscsi_conn_get_addr_param", (void *)&klpe_iscsi_conn_get_addr_param,
	  "libiscsi" },
	{ "iscsi_host_add", (void *)&klpe_iscsi_host_add, "libiscsi" },
	{ "iscsi_host_alloc", (void *)&klpe_iscsi_host_alloc, "libiscsi" },
	{ "iscsi_host_free", (void *)&klpe_iscsi_host_free, "libiscsi" },
	{ "iscsi_host_get_param", (void *)&klpe_iscsi_host_get_param,
	  "libiscsi" },
	{ "iscsi_host_remove", (void *)&klpe_iscsi_host_remove, "libiscsi" },
	{ "iscsi_max_lun", (void *)&klpe_iscsi_max_lun, "iscsi_tcp" },
	{ "iscsi_session_setup", (void *)&klpe_iscsi_session_setup,
	  "libiscsi" },
	{ "iscsi_session_teardown", (void *)&klpe_iscsi_session_teardown,
	  "libiscsi" },
	{ "iscsi_sw_tcp_scsi_transport",
	  (void *)&klpe_iscsi_sw_tcp_scsi_transport, "iscsi_tcp" },
	{ "iscsi_sw_tcp_sht", (void *)&klpe_iscsi_sw_tcp_sht, "iscsi_tcp" },
	{ "iscsi_sw_tcp_transport", (void *)&klpe_iscsi_sw_tcp_transport,
	  "iscsi_tcp" },
	{ "iscsi_tcp_r2tpool_alloc", (void *)&klpe_iscsi_tcp_r2tpool_alloc,
	  "libiscsi_tcp" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1210662_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1210662_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
