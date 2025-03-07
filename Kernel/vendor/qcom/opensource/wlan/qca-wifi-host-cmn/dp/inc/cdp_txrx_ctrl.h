/*
 * Copyright (c) 2016-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: cdp_txrx_ctrl.h
 * Define the host data path control API functions
 * called by the host control SW and the OS interface module
 */

#ifndef _CDP_TXRX_CTRL_H_
#define _CDP_TXRX_CTRL_H_
#include "cdp_txrx_handle.h"
#include "cdp_txrx_cmn_struct.h"
#include "cdp_txrx_cmn.h"
#include "cdp_txrx_ops.h"

static inline int cdp_is_target_ar900b
	(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_is_target_ar900b)
		return 0;

	return soc->ops->ctrl_ops->txrx_is_target_ar900b(soc);
}


/* WIN */
static inline int
cdp_mempools_attach(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_mempools_attach)
		return 0;

	return soc->ops->ctrl_ops->txrx_mempools_attach(soc);
}


#if defined(ATH_SUPPORT_NAC) || defined(ATH_SUPPORT_NAC_RSSI)
/**
 * cdp_update_filter_neighbour_peers() - update the neighbour peer addresses
 * @soc: the pointer to soc object
 * @vdev_id: id of the pointer to vdev
 * @cmd: add/del entry into peer table
 * @macaddr: the address of neighbour peer
 *
 *  This defines interface function to update neighbour peers addresses
 *  which needs to be filtered
 *
 * Return: int
 */
static inline int
cdp_update_filter_neighbour_peers(ol_txrx_soc_handle soc,
	uint8_t vdev_id, uint32_t cmd, uint8_t *macaddr)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->mon_ops ||
	    !soc->ops->mon_ops->txrx_update_filter_neighbour_peers)
		return 0;

	return soc->ops->mon_ops->txrx_update_filter_neighbour_peers
			(soc, vdev_id, cmd, macaddr);
}
#endif /* ATH_SUPPORT_NAC || ATH_SUPPORT_NAC_RSSI*/

/**
 * cdp_update_mon_mac_filter() - update the monitor buffer and status filter
 * @soc: the pointer to soc object
 * @vdev_id: id of the pointer to vdev
 * @cmd: add/del entry into peer table
 *
 * This defines interface function to set/reset monitor filter
 * in case of special vap (scan radio)
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_update_mon_mac_filter(ol_txrx_soc_handle soc,
			  uint8_t vdev_id, uint32_t cmd)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->mon_ops ||
	    !soc->ops->mon_ops->txrx_update_mon_mac_filter)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->mon_ops->txrx_update_mon_mac_filter
			(soc, vdev_id, cmd);
}

#ifdef WLAN_SUPPORT_MSCS
/**
 * cdp_record_vdev_mscs_params() - record the MSCS data and send it to the
 *                                 Data path
 * @soc: the pointer to soc object
 * @vdev_id: id of the pointer to vdev
 * @macaddr: the address of neighbour peer
 * @mscs_params: Structure having MSCS params obtained from handshake
 * @active: Flag to set MSCS active/inactive
 *
 * This defines interface function to record the MSCS procedure
 * based data parameters so that the data path layer can access it
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_record_vdev_mscs_params(ol_txrx_soc_handle soc, uint8_t
		*macaddr, uint8_t vdev_id, struct cdp_mscs_params *mscs_params,
		bool active)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_record_mscs_params)
		return QDF_STATUS_E_FAILURE;
	return soc->ops->ctrl_ops->txrx_record_mscs_params
			(soc, macaddr, vdev_id, mscs_params, active);
}
#endif

/**
 * cdp_set_pdev_reo_dest() - set the Reo Destination ring for the pdev
 * @soc: pointer to the soc
 * @pdev_id: id of the data physical device object
 * @val: the Reo destination ring index (1 to 4)
 *
 * This will be used to configure the Reo Destination ring for this pdev.
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_set_pdev_reo_dest(ol_txrx_soc_handle soc,
		      uint8_t pdev_id, enum cdp_host_reo_dest_ring val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_pdev_reo_dest)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_set_pdev_reo_dest
			(soc, pdev_id, val);
}

/**
 * cdp_get_pdev_reo_dest() - get the Reo Destination ring for the pdev
 * @soc: pointer to the soc
 * @pdev_id: id of physical device object
 *
 * Return: the Reo destination ring index (1 to 4), 0 if not supported.
 */
static inline enum cdp_host_reo_dest_ring
cdp_get_pdev_reo_dest(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return cdp_host_reo_dest_ring_unknown;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_pdev_reo_dest)
		return cdp_host_reo_dest_ring_unknown;

	return soc->ops->ctrl_ops->txrx_get_pdev_reo_dest(soc, pdev_id);
}

/* Is this similar to ol_txrx_peer_state_update() in MCL */

/**
 * cdp_peer_authorize() - Update the authorize peer object at association time
 * @soc: pointer to the soc
 * @vdev_id: id of the pointer to vdev
 * @peer_mac: mac address of the node's object
 * @authorize: either to authorize or unauthorize peer
 *
 * For the host-based implementation of rate-control, it
 * updates the peer/node-related parameters within rate-control
 * context of the peer at association.
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_peer_authorize(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *peer_mac,
		   u_int32_t authorize)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_peer_authorize)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_peer_authorize
			(soc, vdev_id, peer_mac, authorize);
}

/**
 * cdp_peer_get_authorize() - Get per authorize status
 * @soc: pointer to the soc
 * @vdev_id: id of the pointer to vdev
 * @peer_mac: mac address of the node's object
 *
 * Return: true is peer is authorized, false otherwise
 */
static inline bool
cdp_peer_get_authorize(ol_txrx_soc_handle soc, uint8_t vdev_id,
		       uint8_t *peer_mac)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return false;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_peer_get_authorize)
		return false;

	return soc->ops->ctrl_ops->txrx_peer_get_authorize
			(soc, vdev_id, peer_mac);
}

static inline void cdp_tx_flush_buffers
(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->tx_flush_buffers)
		return;

	soc->ops->ctrl_ops->tx_flush_buffers(soc, vdev_id);
}

static inline QDF_STATUS cdp_txrx_get_vdev_param(ol_txrx_soc_handle soc,
						 uint8_t vdev_id,
						 enum cdp_vdev_param_type type,
						 cdp_config_param_type *val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_vdev_param) {
		dp_cdp_debug("callback not registered:");
		return QDF_STATUS_E_FAILURE;
	}

	return soc->ops->ctrl_ops->txrx_get_vdev_param(soc, vdev_id,
						       type, val);
}

static inline QDF_STATUS
cdp_txrx_set_vdev_param(ol_txrx_soc_handle soc,
			uint8_t vdev_id, enum cdp_vdev_param_type type,
			cdp_config_param_type val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_vdev_param) {
		dp_cdp_nofl_debug("NULL vdev params callback");
		return QDF_STATUS_E_FAILURE;
	}

	return soc->ops->ctrl_ops->txrx_set_vdev_param(soc, vdev_id,
						       type, val);
}

static inline QDF_STATUS
cdp_txrx_set_psoc_param(ol_txrx_soc_handle soc,
			enum cdp_psoc_param_type type,
			cdp_config_param_type val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_psoc_param)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_set_psoc_param(soc, type, val);
}

static inline QDF_STATUS
cdp_txrx_get_psoc_param(ol_txrx_soc_handle soc,
			enum cdp_psoc_param_type type,
			cdp_config_param_type *val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_psoc_param)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_get_psoc_param(soc, type, val);
}

static inline
QDF_STATUS cdp_vdev_alloc_vdev_stats_id(ol_txrx_soc_handle soc,
					uint8_t *vdev_stats_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_alloc_vdev_stats_id)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->host_stats_ops->txrx_alloc_vdev_stats_id
			(soc, vdev_stats_id);
}

static inline
void cdp_vdev_reset_vdev_stats_id(ol_txrx_soc_handle soc,
				  uint8_t vdev_stats_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->host_stats_ops ||
	    !soc->ops->host_stats_ops->txrx_reset_vdev_stats_id)
		return;

	soc->ops->host_stats_ops->txrx_reset_vdev_stats_id(soc, vdev_stats_id);
}

#ifdef VDEV_PEER_PROTOCOL_COUNT
/**
 * cdp_set_vdev_peer_protocol_count() - set per-peer protocol count tracking
 * @soc: pointer to the soc
 * @vdev_id: the data virtual device object
 * @enable: enable per-peer protocol count
 *
 * Set per-peer protocol count feature enable
 *
 * Return: void
 */
static inline
void cdp_set_vdev_peer_protocol_count(ol_txrx_soc_handle soc, int8_t vdev_id,
				      bool enable)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_enable_peer_protocol_count)
		return;

	soc->ops->ctrl_ops->txrx_enable_peer_protocol_count(soc, vdev_id,
							    enable);
}

/**
 * cdp_set_vdev_peer_protocol_drop_mask() - set per-peer protocol drop mask
 * @soc: pointer to the soc
 * @vdev_id: ID of the data virtual device object
 * @drop_mask: drop_mask
 *
 * Set per-peer protocol drop_mask
 *
 * Return: void
 */
static inline
void cdp_set_vdev_peer_protocol_drop_mask(ol_txrx_soc_handle soc,
					  int8_t vdev_id, int drop_mask)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_peer_protocol_drop_mask)
		return;

	soc->ops->ctrl_ops->txrx_set_peer_protocol_drop_mask(soc, vdev_id,
							 drop_mask);
}

/**
 * cdp_is_vdev_peer_protocol_count_enabled() - whether peer-protocol tracking
 *                                             enabled
 * @soc: pointer to the soc
 * @vdev_id: ID of the data virtual device object
 *
 * Get whether peer protocol count feature enabled or not
 *
 * Return: whether feature enabled or not
 */
static inline
int cdp_is_vdev_peer_protocol_count_enabled(ol_txrx_soc_handle soc,
					    int8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_is_peer_protocol_count_enabled)
		return 0;

	return soc->ops->ctrl_ops->txrx_is_peer_protocol_count_enabled(soc,
								   vdev_id);
}

/**
 * cdp_get_peer_protocol_drop_mask() - get per-peer protocol count drop-mask
 * @soc: pointer to the soc
 * @vdev_id: ID of the data virtual device object
 *
 * Get peer-protocol-count drop-mask
 *
 * Return: peer-protocol-count drop-mask
 */
static inline
int cdp_get_peer_protocol_drop_mask(ol_txrx_soc_handle soc, int8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_peer_protocol_drop_mask)
		return 0;

	return soc->ops->ctrl_ops->txrx_get_peer_protocol_drop_mask(soc,
								    vdev_id);
}

/*
 * Rx-Ingress and Tx-Egress are in the lower level DP layer
 * Rx-Egress and Tx-ingress are handled in osif layer for DP
 * So
 * Rx-Ingress and Tx-Egress definitions are in DP layer
 * Rx-Egress and Tx-ingress mask definitions are here below
 */
#define VDEV_PEER_PROTOCOL_RX_INGRESS_MASK 1
#define VDEV_PEER_PROTOCOL_TX_INGRESS_MASK 2
#define VDEV_PEER_PROTOCOL_RX_EGRESS_MASK 4
#define VDEV_PEER_PROTOCOL_TX_EGRESS_MASK 8

#else
#define cdp_set_vdev_peer_protocol_count(soc, vdev_id, enable)
#define cdp_set_vdev_peer_protocol_drop_mask(soc, vdev_id, drop_mask)
#define cdp_is_vdev_peer_protocol_count_enabled(soc, vdev_id) 0
#define cdp_get_peer_protocol_drop_mask(soc, vdev_id) 0
#endif

/**
 * cdp_txrx_set_pdev_param() - set pdev parameter
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 * @type: param type
 * @val: value
 *
 * Return: status: 0 - Success, non-zero: Failure
 */
static inline QDF_STATUS cdp_txrx_set_pdev_param(ol_txrx_soc_handle soc,
						 uint8_t pdev_id,
						 enum cdp_pdev_param_type type,
						 cdp_config_param_type val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_pdev_param)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_set_pdev_param
			(soc, pdev_id, type, val);
}

/**
 * cdp_txrx_set_peer_param() - set pdev parameter
 * @soc: opaque soc handle
 * @vdev_id: id of data path vdev handle
 * @peer_mac: peer mac address
 * @type: param type
 * @val: value
 *
 * Return: status: 0 - Success, non-zero: Failure
 */
static inline QDF_STATUS cdp_txrx_set_peer_param(ol_txrx_soc_handle soc,
						 uint8_t vdev_id,
						 uint8_t *peer_mac,
						 enum cdp_peer_param_type type,
						 cdp_config_param_type val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_peer_param)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_set_peer_param
			(soc, vdev_id, peer_mac, type, val);
}

/**
 * cdp_txrx_get_peer_param() - set pdev parameter
 * @soc: opaque soc handle
 * @vdev_id: id of data path vdev handle
 * @peer_mac: peer mac address
 * @type: param type
 * @val: address of buffer
 *
 * Return: status
 */
static inline QDF_STATUS cdp_txrx_get_peer_param(ol_txrx_soc_handle soc,
						 uint8_t vdev_id,
						 uint8_t *peer_mac,
						 enum cdp_peer_param_type type,
						 cdp_config_param_type *val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_peer_param)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_get_peer_param
			(soc, vdev_id, peer_mac, type, val);
}

#ifdef QCA_MULTIPASS_SUPPORT
static inline void
cdp_peer_set_vlan_id(ol_txrx_soc_handle soc, uint8_t vdev_id,
		     uint8_t *peer_mac, uint16_t vlan_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_peer_set_vlan_id)
		return;

	soc->ops->ctrl_ops->txrx_peer_set_vlan_id(soc, vdev_id, peer_mac,
						  vlan_id);
}
#endif

/**
 * cdp_txrx_get_pdev_param() - get pdev parameter
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 * @type: param type
 * @value: address of value buffer
 *
 * Return: status
 */
static inline QDF_STATUS cdp_txrx_get_pdev_param(ol_txrx_soc_handle soc,
						 uint8_t pdev_id,
						 enum cdp_pdev_param_type type,
						 cdp_config_param_type *value)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_pdev_param)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_get_pdev_param
			(soc, pdev_id, type, value);
}

/**
 * cdp_txrx_peer_protocol_cnt() - set peer protocol count
 * @soc: opaque soc handle
 * @vdev_id: vdev id
 * @nbuf: data packet
 * @is_egress: whether egress or ingress
 * @is_rx: whether tx or rx
 *
 * Return: void
 */
#ifdef VDEV_PEER_PROTOCOL_COUNT
static inline void
cdp_txrx_peer_protocol_cnt(ol_txrx_soc_handle soc,
			   int8_t vdev_id,
			   qdf_nbuf_t nbuf,
			   enum vdev_peer_protocol_enter_exit is_egress,
			   enum vdev_peer_protocol_tx_rx is_rx)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_peer_protocol_cnt)
		return;

	soc->ops->ctrl_ops->txrx_peer_protocol_cnt(soc, vdev_id, nbuf,
						   is_egress, is_rx);
}
#else
#define cdp_txrx_peer_protocol_cnt(soc, vdev_id, nbuf, is_egress, is_rx)
#endif

/**
 * cdp_enable_peer_based_pktlog()- Set flag in peer structure
 * @soc: pointer to the soc
 * @pdev_id: id of the data physical device object
 * @enable: enable or disable peer based filter based pktlog
 * @peer_macaddr: Mac address of peer which needs to be
 * filtered
 *
 * This function will set flag in peer structure if peer based filtering
 * is enabled for pktlog
 *
 * Return: int
 */
static inline int
cdp_enable_peer_based_pktlog(ol_txrx_soc_handle soc, uint8_t pdev_id,
			     char *peer_macaddr,
			     uint8_t enable)
{
	if (!soc || !soc->ops) {
		QDF_TRACE_ERROR(QDF_MODULE_ID_DP,
				"%s invalid instance", __func__);
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->enable_peer_based_pktlog)
		return 0;

	return soc->ops->ctrl_ops->enable_peer_based_pktlog
			(soc, pdev_id, peer_macaddr, enable);
}

/**
 * cdp_calculate_delay_stats()- get rx delay stats
 * @soc: pointer to the soc
 * @vdev_id: id of vdev handle
 * @nbuf: nbuf which is passed
 *
 * This function will calculate rx delay statistics.
 */
static inline QDF_STATUS
cdp_calculate_delay_stats(ol_txrx_soc_handle soc, uint8_t vdev_id,
			  qdf_nbuf_t nbuf)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->calculate_delay_stats) {
		dp_cdp_debug("callback not registered:");
		return QDF_STATUS_E_FAILURE;
	}

	return soc->ops->ctrl_ops->calculate_delay_stats(soc, vdev_id, nbuf);
}

/**
 * cdp_wdi_event_sub() - Subscribe to a specified WDI event.
 * @soc: pointer to the soc
 * @pdev_id: id of the data physical device object
 * @event_cb_sub: the callback and context for the event subscriber
 * @event: which event's notifications are being subscribed to
 *
 * This function adds the provided wdi_event_subscribe object to a list of
 * subscribers for the specified WDI event.
 * When the event in question happens, each subscriber for the event will
 * have their callback function invoked.
 * The order in which callback functions from multiple subscribers are
 * invoked is unspecified.
 *
 * Return: int
 */
static inline int
cdp_wdi_event_sub(ol_txrx_soc_handle soc, uint8_t pdev_id,
		  wdi_event_subscribe *event_cb_sub, uint32_t event)
{

	if (!soc || !soc->ops) {
		dp_cdp_debug("invalid instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_wdi_event_sub)
		return 0;

	return soc->ops->ctrl_ops->txrx_wdi_event_sub
			(soc, pdev_id, event_cb_sub, event);
}

/**
 * cdp_wdi_event_unsub() - Unsubscribe from a specified WDI event.
 * @soc: pointer to the soc
 * @pdev_id: id of the data physical device object
 * @event_cb_sub: the callback and context for the event subscriber
 * @event: which event's notifications are being subscribed to
 *
 * This function removes the provided event subscription object from the
 * list of subscribers for its event.
 * This function shall only be called if there was a successful prior call
 * to cdp_wdi_event_sub() on the same wdi_event_subscribe object.
 *
 * Return: int
 */
static inline int
cdp_wdi_event_unsub(ol_txrx_soc_handle soc,
		    uint8_t pdev_id, wdi_event_subscribe *event_cb_sub,
		    uint32_t event)
{

	if (!soc || !soc->ops) {
		dp_cdp_debug("invalid instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_wdi_event_unsub)
		return 0;

	return soc->ops->ctrl_ops->txrx_wdi_event_unsub
			(soc, pdev_id, event_cb_sub, event);
}

/**
 * cdp_get_sec_type() - Get security type from the from peer.
 * @soc: pointer to the soc
 * @vdev_id: id of vdev handle
 * @peer_mac: peer mac address
 * @sec_idx: mcast or ucast frame type.
 *
 * This function gets the Security information from the peer handler.
 * The security information is got from the rx descriptor and filled in
 * to the peer handler.
 *
 * Return: int
 */
static inline int
cdp_get_sec_type(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *peer_mac,
		 uint8_t sec_idx)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("invalid instance");
		QDF_BUG(0);
		return A_ERROR;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_sec_type)
		return A_ERROR;

	return soc->ops->ctrl_ops->txrx_get_sec_type
		(soc, vdev_id, peer_mac, sec_idx);
}

/**
  * cdp_set_mgmt_tx_power() - function to set tx power for mgmt frames
  * @soc: pointer to the soc
  * @vdev_id : id of vdev handle
  * @subtype: subtype
  * @tx_power: Tx power
  *
  * Return: QDF_STATUS
  */
static inline QDF_STATUS
cdp_set_mgmt_tx_power(ol_txrx_soc_handle soc,
		      uint8_t vdev_id, uint8_t subtype, uint8_t tx_power)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_update_mgmt_txpow_vdev)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_update_mgmt_txpow_vdev(soc, vdev_id,
							subtype, tx_power);
}

/**
 * cdp_get_pldev() - function to get pktlog device handle
 * @soc: datapath soc handle
 * @pdev_id: physical device id
 *
 * Return: pktlog device handle or NULL
 */
static inline void *
cdp_get_pldev(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			"%s invalid instance", __func__);
		QDF_BUG(0);
		return NULL;
	}

	if (!soc->ops->ctrl_ops || !soc->ops->ctrl_ops->txrx_get_pldev)
		return NULL;

	return soc->ops->ctrl_ops->txrx_get_pldev(soc, pdev_id);
}

#if defined(WLAN_CFR_ENABLE) && defined(WLAN_ENH_CFR_ENABLE)
/**
 * cdp_cfr_filter() - Configure Host RX monitor status ring for CFR
 * @soc: SOC TXRX handle
 * @pdev_id: ID of the physical device object
 * @enable: Enable or disable CFR
 * @filter_val: Flag to select filter for monitor mode
 * @cfr_enable_monitor_mode: Flag to be enabled when scan radio is brought up
 * in special vap mode
 */
static inline void
cdp_cfr_filter(ol_txrx_soc_handle soc,
	       uint8_t pdev_id,
	       bool enable, struct cdp_monitor_filter *filter_val,
	       bool cfr_enable_monitor_mode)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "%s invalid instance", __func__);
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->mon_ops || !soc->ops->mon_ops->txrx_cfr_filter)
		return;

	soc->ops->mon_ops->txrx_cfr_filter(soc, pdev_id, enable, filter_val,
					   cfr_enable_monitor_mode);
}

/**
 * cdp_get_cfr_rcc() - get cfr rcc config
 * @soc: Datapath soc handle
 * @pdev_id: id of objmgr pdev
 *
 * Return: true/false based on cfr mode setting
 */
static inline
bool cdp_get_cfr_rcc(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "%s invalid instance", __func__);
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cfr_ops || !soc->ops->cfr_ops->txrx_get_cfr_rcc)
		return 0;

	return soc->ops->cfr_ops->txrx_get_cfr_rcc(soc, pdev_id);
}

/**
 * cdp_set_cfr_rcc() - enable/disable cfr rcc config
 * @soc: Datapath soc handle
 * @pdev_id: id of objmgr pdev
 * @enable: Enable/Disable cfr rcc mode
 *
 * Return: none
 */
static inline
void cdp_set_cfr_rcc(ol_txrx_soc_handle soc, uint8_t pdev_id, bool enable)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "%s invalid instance", __func__);
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cfr_ops || !soc->ops->cfr_ops->txrx_set_cfr_rcc)
		return;

	return soc->ops->cfr_ops->txrx_set_cfr_rcc(soc, pdev_id, enable);
}

/**
 * cdp_get_cfr_dbg_stats() - Get debug statistics for CFR
 * @soc: SOC TXRX handle
 * @pdev_id: ID of the physical device object
 * @buf: CFR RCC debug statistics buffer
 *
 * Return: None
 */
static inline void
cdp_get_cfr_dbg_stats(ol_txrx_soc_handle soc, uint8_t pdev_id,
		      struct cdp_cfr_rcc_stats *buf)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "%s invalid instance", __func__);
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cfr_ops || !soc->ops->cfr_ops->txrx_get_cfr_dbg_stats)
		return;

	soc->ops->cfr_ops->txrx_get_cfr_dbg_stats(soc, pdev_id, buf);
}

/**
 * cdp_cfr_clr_dbg_stats() - Clear debug statistics for CFR
 * @soc: SOC TXRX handle
 * @pdev_id: ID of the physical device object
 */
static inline void
cdp_cfr_clr_dbg_stats(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "%s invalid instance", __func__);
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cfr_ops || !soc->ops->cfr_ops->txrx_clear_cfr_dbg_stats)
		return;

	soc->ops->cfr_ops->txrx_clear_cfr_dbg_stats(soc, pdev_id);
}
#endif

#if defined(WLAN_TX_PKT_CAPTURE_ENH) || defined(WLAN_RX_PKT_CAPTURE_ENH)
/**
 * cdp_update_peer_pkt_capture_params() - Sets Rx & Tx Capture params for a peer
 * @soc: SOC TXRX handle
 * @pdev_id: id of CDP pdev pointer
 * @is_rx_pkt_cap_enable: enable/disable rx pkt capture for this peer
 * @is_tx_pkt_cap_enable: enable/disable tx pkt capture for this peer
 * @peer_mac: MAC address of peer for which pkt_cap is to be enabled/disabled
 *
 * Return: Success when matching peer is found & flags are set, error otherwise
 */
static inline QDF_STATUS
cdp_update_peer_pkt_capture_params(ol_txrx_soc_handle soc,
				   uint8_t pdev_id,
				   bool is_rx_pkt_cap_enable,
				   uint8_t is_tx_pkt_cap_enable,
				   uint8_t *peer_mac)
{
	if (!soc || !soc->ops) {
		dp_err("Invalid SOC instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_update_peer_pkt_capture_params)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_update_peer_pkt_capture_params
			(soc, pdev_id, is_rx_pkt_cap_enable,
			 is_tx_pkt_cap_enable, peer_mac);
}
#endif /* WLAN_TX_PKT_CAPTURE_ENH || WLAN_RX_PKT_CAPTURE_ENH */

#ifdef WLAN_SUPPORT_RX_PROTOCOL_TYPE_TAG
/**
 * cdp_update_pdev_rx_protocol_tag() - wrapper function to set the protocol
 *                                    tag in CDP layer from cfg layer
 * @soc: SOC TXRX handle
 * @pdev_id: id of CDP pdev pointer
 * @protocol_mask: Bitmap for protocol for which tagging is enabled
 * @protocol_type: Protocol type for which the tag should be update
 * @tag: Actual tag value for the given prototype
 * Return: Returns QDF_STATUS_SUCCESS/FAILURE
 */
static inline QDF_STATUS
cdp_update_pdev_rx_protocol_tag(ol_txrx_soc_handle soc,
				uint8_t pdev_id, uint32_t protocol_mask,
				uint16_t protocol_type, uint16_t tag)
{
	if (!soc || !soc->ops) {
		dp_err("Invalid SOC instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_update_pdev_rx_protocol_tag)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_update_pdev_rx_protocol_tag
			(soc, pdev_id, protocol_mask, protocol_type, tag);
}

#ifdef WLAN_SUPPORT_RX_TAG_STATISTICS
/**
 * cdp_dump_pdev_rx_protocol_tag_stats() - wrapper function to dump the protocol
 *				tag statistics for given or all protocols
 * @soc: SOC TXRX handle
 * @pdev_id: id of CDP pdev pointer
 * @protocol_type: Protocol type for which the tag should be update
 *
 * Return: Returns QDF_STATUS_SUCCESS/FAILURE
 */
static inline QDF_STATUS
cdp_dump_pdev_rx_protocol_tag_stats(ol_txrx_soc_handle soc,
				    uint8_t pdev_id,
				    uint16_t protocol_type)
{
	if (!soc || !soc->ops) {
		dp_err("Invalid SOC instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_dump_pdev_rx_protocol_tag_stats)
		return QDF_STATUS_E_FAILURE;

	soc->ops->ctrl_ops->txrx_dump_pdev_rx_protocol_tag_stats(soc, pdev_id,
						protocol_type);
	return QDF_STATUS_SUCCESS;
}
#endif /* WLAN_SUPPORT_RX_TAG_STATISTICS */
#endif /* WLAN_SUPPORT_RX_PROTOCOL_TYPE_TAG */

#ifdef ATH_SUPPORT_NAC_RSSI
/**
  * cdp_vdev_config_for_nac_rssi() - To invoke dp callback for nac rssi config
  * @soc: soc pointer
  * @vdev_id: id of vdev
  * @nac_cmd: specifies nac_rss config action add, del, list
  * @bssid: Neighbour bssid
  * @client_macaddr: Non-Associated client MAC
  * @chan_num: channel number to scan
  *
  * Return: QDF_STATUS
  */
static inline QDF_STATUS cdp_vdev_config_for_nac_rssi(ol_txrx_soc_handle soc,
		uint8_t vdev_id, enum cdp_nac_param_cmd nac_cmd,
		char *bssid, char *client_macaddr, uint8_t chan_num)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			"%s invalid instance", __func__);
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->mon_ops ||
			!soc->ops->mon_ops->txrx_vdev_config_for_nac_rssi)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->mon_ops->txrx_vdev_config_for_nac_rssi(soc, vdev_id,
			nac_cmd, bssid, client_macaddr, chan_num);
}

/**
 * cdp_vdev_get_neighbour_rssi() - invoke dp callback to get rssi value of nac
 * @soc: soc pointer
 * @vdev_id: id of vdev
 * @macaddr: Non-Associated client MAC
 * @rssi: rssi
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS cdp_vdev_get_neighbour_rssi(ol_txrx_soc_handle soc,
						     uint8_t vdev_id,
						     char *macaddr,
						     uint8_t *rssi)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "%s invalid instance", __func__);
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->mon_ops ||
	    !soc->ops->mon_ops->txrx_vdev_get_neighbour_rssi)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->mon_ops->txrx_vdev_get_neighbour_rssi(soc, vdev_id,
								macaddr,
								rssi);
}
#endif

#ifdef WLAN_SUPPORT_RX_FLOW_TAG
/**
 * cdp_set_rx_flow_tag() - wrapper function to set the flow
 *                         tag in CDP layer from cfg layer
 * @soc: SOC TXRX handle
 * @pdev_id: id of CDP pdev pointer
 * @flow_info: Flow 5-tuple, along with tag, if any, that needs to added/deleted
 *
 * Return: Success when add/del operation is successful, error otherwise
 */
static inline QDF_STATUS
cdp_set_rx_flow_tag(ol_txrx_soc_handle soc, uint8_t pdev_id,
		    struct cdp_rx_flow_info *flow_info)
{
	if (!soc || !soc->ops) {
		dp_err("Invalid SOC instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_rx_flow_tag)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_set_rx_flow_tag(soc, pdev_id,
				   flow_info);
}

/**
 * cdp_dump_rx_flow_tag_stats() - wrapper function to dump the flow
 *                                tag statistics for given flow
 * @soc: SOC TXRX handle
 * @pdev_id: id of CDP pdev
 * @flow_info: Flow tuple for which we want to print the statistics
 *
 * Return: Success when flow is found and stats are printed, error otherwise
 */
static inline QDF_STATUS
cdp_dump_rx_flow_tag_stats(ol_txrx_soc_handle soc, uint8_t pdev_id,
			   struct cdp_rx_flow_info *flow_info)
{
	if (!soc || !soc->ops) {
		dp_err("Invalid SOC instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_dump_rx_flow_tag_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_dump_rx_flow_tag_stats(soc,
								pdev_id,
								flow_info);
}
#endif /* WLAN_SUPPORT_RX_FLOW_TAG */

/**
 * cdp_txrx_peer_flush_frags() - flush frags for peer
 * @soc: pointer to the soc
 * @vdev_id: vdev id
 * @peer_mac: peer MAC address
 *
 * Get peer-protocol-count drop-mask
 *
 * Return: peer-protocol-count drop-mask
 */
static inline
void cdp_txrx_peer_flush_frags(ol_txrx_soc_handle soc, uint8_t vdev_id,
			       uint8_t *peer_mac)
{
	if (!soc || !soc->ops) {
		dp_cdp_err("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_peer_flush_frags)
		return;

	return soc->ops->ctrl_ops->txrx_peer_flush_frags(soc, vdev_id,
							 peer_mac);
}

#if defined(WLAN_FEATURE_TSF_AUTO_REPORT) || defined(WLAN_CONFIG_TX_DELAY)
/**
 * cdp_set_delta_tsf() - wrapper function to set delta_tsf
 * @soc: SOC TXRX handle
 * @vdev_id: vdev id
 * @delta_tsf: difference between TSF clock and qtimer
 *
 * Return: None
 */
static inline void cdp_set_delta_tsf(ol_txrx_soc_handle soc, uint8_t vdev_id,
				     uint32_t delta_tsf)
{
	if (!soc || !soc->ops) {
		dp_cdp_err("Invalid instance");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_delta_tsf)
		return;

	soc->ops->ctrl_ops->txrx_set_delta_tsf(soc, vdev_id, delta_tsf);
}
#endif
#ifdef WLAN_FEATURE_TSF_UPLINK_DELAY
/**
 * cdp_set_tsf_ul_delay_report() - Enable or disable reporting uplink delay
 * @soc: SOC TXRX handle
 * @vdev_id: vdev id
 * @enable: true to enable and false to disable
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS cdp_set_tsf_ul_delay_report(ol_txrx_soc_handle soc,
						     uint8_t vdev_id,
						     bool enable)
{
	if (!soc || !soc->ops) {
		dp_cdp_err("Invalid SOC instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_tsf_ul_delay_report)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_set_tsf_ul_delay_report(soc, vdev_id,
								enable);
}

/**
 * cdp_get_uplink_delay() - Get uplink delay value
 * @soc: SOC TXRX handle
 * @vdev_id: vdev id
 * @val: pointer to save uplink delay value
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS cdp_get_uplink_delay(ol_txrx_soc_handle soc,
					      uint32_t vdev_id, uint32_t *val)
{
	if (!soc || !soc->ops) {
		dp_cdp_err("Invalid SOC instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!val) {
		dp_cdp_err("Invalid params val");
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_uplink_delay)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_get_uplink_delay(soc, vdev_id, val);
}
#endif /* WLAN_FEATURE_TSF_UPLINK_DELAY */

#ifdef WLAN_FEATURE_UL_JITTER
/**
 * cdp_get_uplink_jitter() - Get uplink delay jitter
 * @soc: SOC TXRX handle
 * @vdev_id: vdev id
 * @val: pointer to save uplink jitter value
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS cdp_get_uplink_jitter(ol_txrx_soc_handle soc,
					       uint32_t vdev_id, uint32_t *val)
{
	if (!soc || !soc->ops) {
		dp_cdp_err("Invalid SOC instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!val) {
		dp_cdp_err("Invalid params val");
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->avg_ul_delay_jitter_stats)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->avg_ul_delay_jitter_stats(soc, vdev_id, val);
}

/**
 * cdp_get_txrx_nss(): function to collect txrx nss
 * @soc: soc handle
 * @vdev_id: virtual device ID
 * @req: nss stats array
 *
 * return: status
 */
static inline
int cdp_get_txrx_nss(ol_txrx_soc_handle soc, uint8_t vdev_id, int **req)
{
	if (!soc || !soc->ops || !soc->ops->ctrl_ops || !req) {
		dp_cdp_debug("Invalid Instance:");
		QDF_ASSERT(0);
		return 0;
	}

	if (soc->ops->ctrl_ops->txrx_nss_request)
		return soc->ops->ctrl_ops->txrx_nss_request(soc, vdev_id,
							    req);

	return 0;
}

#endif /* WLAN_FEATURE_UL_JITTER */

#ifdef QCA_UNDECODED_METADATA_SUPPORT
/**
 * cdp_txrx_set_pdev_phyrx_error_mask() - set phyrx error mask
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 * @mask: mask to configure 0 to 31 phy error
 * @mask_cont: mask to configure 32 to 63 phy error
 *
 * Return: status: 0 - Success, non-zero: Failure
 */
static inline
QDF_STATUS cdp_txrx_set_pdev_phyrx_error_mask(ol_txrx_soc_handle soc,
					      uint8_t pdev_id, uint32_t mask,
					      uint32_t mask_cont)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_pdev_phyrx_error_mask)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_set_pdev_phyrx_error_mask
			(soc, pdev_id, mask, mask_cont);
}

static inline
QDF_STATUS cdp_txrx_get_pdev_phyrx_error_mask(ol_txrx_soc_handle soc,
					      uint8_t pdev_id, uint32_t *mask,
					      uint32_t *mask_cont)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_pdev_phyrx_error_mask)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_get_pdev_phyrx_error_mask
			(soc, pdev_id, mask, mask_cont);
}
#endif

#ifdef DP_UMAC_HW_RESET_SUPPORT
/**
 * cdp_get_umac_reset_in_progress_state() - API to get the umac reset in
 *                                          progress state
 * @soc: opaque soc handle
 *
 * Return: Umac reset in progress state
 */
static inline enum cdp_umac_reset_state
cdp_get_umac_reset_in_progress_state(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid soc or soc->ops:");
		return CDP_UMAC_RESET_INVALID_STATE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->get_umac_reset_in_progress_state)
		return CDP_UMAC_RESET_INVALID_STATE;

	return soc->ops->ctrl_ops->get_umac_reset_in_progress_state(soc);
}

/**
 * cdp_umac_reset_is_inprogress() - API to check if umac reset is in progress
 * @soc: opaque soc handle
 *
 * Return: true if umac reset is in progress, else false.
 */
static inline bool
cdp_umac_reset_is_inprogress(ol_txrx_soc_handle soc)
{
	enum cdp_umac_reset_state state;

	state = cdp_get_umac_reset_in_progress_state(soc);

	if (state == CDP_UMAC_RESET_IN_PROGRESS ||
	    state == CDP_UMAC_RESET_IN_PROGRESS_DURING_BUFFER_WINDOW)
		return true;
	else
		return false;
}
#else
static inline bool
cdp_umac_reset_is_inprogress(ol_txrx_soc_handle soc)
{
	return false;
}
#endif

#ifdef WLAN_SUPPORT_RX_FISA
static inline
QDF_STATUS cdp_txrx_fisa_config(struct cdp_soc_t *soc, uint8_t pdev_id,
				enum cdp_fisa_config_id config_id,
				union cdp_fisa_config *cfg)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops || !soc->ops->ctrl_ops->txrx_fisa_config)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_fisa_config(soc, pdev_id, config_id,
						    cfg);
}
#endif

/**
 * cdp_get_pdev_mlo_timestamp_offset() - get MLO timestamp offset for the pdev
 * @soc: pointer to the soc
 * @pdev_id: id of physical device object
 *
 * Return: the MLO timestamp offset for the pdev
 */
static inline uint64_t
cdp_get_pdev_mlo_timestamp_offset(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_pdev_mlo_timestamp_offset)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_get_pdev_mlo_timestamp_offset
			(soc, pdev_id);
}

/**
 * cdp_set_req_buff_descs - set required RX descriptors for connection
 * @soc: DP soc reference
 * @req_rx_buff_descs: required rx descriptors
 * @pdev_id: pdev id
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_set_req_buff_descs(struct cdp_soc_t *soc,
		       uint64_t req_rx_buff_descs,
		       uint32_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_set_req_buff_descs)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_set_req_buff_descs(soc,
						req_rx_buff_descs, pdev_id);
}

/**
 * cdp_get_num_buff_descs_info - Get Buffer descriptors info
 * @soc: DP soc reference
 * @req_rx_buff_descs: required rx descriptors
 * @in_use_rx_buff_descs: rx descriptors in use
 * @pdev_id: pdev id
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_get_num_buff_descs_info(struct cdp_soc_t *soc,
			    uint64_t *req_rx_buff_descs,
			    uint64_t *in_use_rx_buff_descs,
			    uint32_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_get_num_buff_descs_info)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_get_num_buff_descs_info(soc,
						req_rx_buff_descs,
						in_use_rx_buff_descs, pdev_id);
}

/**
 * cdp_buffers_replenish_on_demand - Replenish Rx buffers on demand
 * @soc: DP soc reference
 * @num_buffers: Number of Rx buffers to replenish
 * @pdev_id: pdev id
 *
 * Return: QDF_STATUS
 */
static inline uint32_t
cdp_buffers_replenish_on_demand(struct cdp_soc_t *soc,
				uint32_t num_buffers,
				uint32_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->txrx_buffers_replenish_on_demand)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->txrx_buffers_replenish_on_demand(soc,
						num_buffers, pdev_id);
}
#endif /* _CDP_TXRX_CTRL_H_ */
