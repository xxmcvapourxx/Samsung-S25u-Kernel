/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
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
 * DOC: declare various api which shall be used by
 * IPA user configuration and target interface
 */

#ifndef _WLAN_IPA_MAIN_H_
#define _WLAN_IPA_MAIN_H_

#ifdef IPA_OFFLOAD

#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_ipa_public_struct.h>
#include <wlan_ipa_priv.h>
#include "cfg_ucfg_api.h"

/* Declare a variable for IPA instancess added based on pdev */
extern uint8_t g_instances_added;
#define IPA_INVALID_HDL 0xFF
#define IPA_OFFLOAD_CFG 0x7D

#define INTRL_MODE_DISABLE 0xEEEEEEEE
#define INTRL_MODE_ENABLE 0x27D
#define INTRL_MODE_RTP_STREAM_FILTER 0x1A7D

#define ipa_fatal(params...) \
	QDF_TRACE_FATAL(QDF_MODULE_ID_IPA, params)
#define ipa_err(params...) \
	QDF_TRACE_ERROR(QDF_MODULE_ID_IPA, params)
#define ipa_warn(params...) \
	QDF_TRACE_WARN(QDF_MODULE_ID_IPA, params)
#define ipa_info(params...) \
	QDF_TRACE_INFO(QDF_MODULE_ID_IPA, params)
#define ipa_debug(params...) \
	QDF_TRACE_DEBUG(QDF_MODULE_ID_IPA, params)

#define ipa_nofl_fatal(params...) \
	QDF_TRACE_FATAL_NO_FL(QDF_MODULE_ID_IPA, params)
#define ipa_nofl_err(params...) \
	QDF_TRACE_ERROR_NO_FL(QDF_MODULE_ID_IPA, params)
#define ipa_nofl_warn(params...) \
	QDF_TRACE_WARN_NO_FL(QDF_MODULE_ID_IPA, params)
#define ipa_nofl_info(params...) \
	QDF_TRACE_INFO_NO_FL(QDF_MODULE_ID_IPA, params)
#define ipa_nofl_debug(params...) \
	QDF_TRACE_DEBUG_NO_FL(QDF_MODULE_ID_IPA, params)

#define ipa_fatal_rl(params...) QDF_TRACE_FATAL_RL(QDF_MODULE_ID_IPA, params)
#define ipa_err_rl(params...) QDF_TRACE_ERROR_RL(QDF_MODULE_ID_IPA, params)
#define ipa_warn_rl(params...) QDF_TRACE_WARN_RL(QDF_MODULE_ID_IPA, params)
#define ipa_info_rl(params...) QDF_TRACE_INFO_RL(QDF_MODULE_ID_IPA, params)
#define ipa_debug_rl(params...) QDF_TRACE_DEBUG_RL(QDF_MODULE_ID_IPA, params)

#define IPA_ENTER() \
	QDF_TRACE_ENTER(QDF_MODULE_ID_IPA, "enter")
#define IPA_EXIT() \
	QDF_TRACE_EXIT(QDF_MODULE_ID_IPA, "exit")

/**
 * ipa_set_cap_offload() - set IPA capability offload support
 * @flag: flag to set
 *
 * Return: None
 */
void ipa_set_cap_offload(bool flag);

/**
 * ipa_set_pld_enable() - set g_ipa_pld_enable
 * @flag: flag to set g_ipa_pld_enable
 *
 * Return: None
 */
void ipa_set_pld_enable(bool flag);

/**
 * ipa_get_pld_enable() - check if IPA is disabled in pld
 *
 * Return: g_ipa_pld_enable
 */
bool ipa_get_pld_enable(void);

/**
 * ipa_set_shared_smmu_enable() - set g_ipa_shared_smmu_enable
 * @flag: flag to set g_ipa_shared_smmu_enable
 *
 * Return: None
 */
void ipa_set_shared_smmu_enable(bool flag);

/**
 * ipa_get_shared_smmu_enable() - check if IPA shared smmu is disabled in pld
 *
 * Return: g_ipa_shared_smmu_enable
 */
bool ipa_get_shared_smmu_enable(void);

/**
 * ipa_check_hw_present() - get IPA hw status
 *
 * ipa_uc_reg_rdyCB is not directly designed to check
 * ipa hw status. This is an undocumented function which
 * has confirmed with IPA team.
 *
 * Return: true - ipa hw present
 *         false - ipa hw not present
 */
bool ipa_check_hw_present(void);

/**
 * ipa_psoc_get_priv_obj() - private API to get ipa psoc object
 * @psoc: psoc object
 *
 * Return: ipa object
 */
static inline struct wlan_ipa_priv *
ipa_psoc_get_priv_obj(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_ipa_priv *ipa_obj;

	ipa_obj = (struct wlan_ipa_priv *)
		wlan_objmgr_psoc_get_comp_private_obj(psoc,
						      WLAN_UMAC_COMP_IPA);

	return ipa_obj;
}

/**
 * ipa_priv_obj_get_psoc() - API to get psoc from IPA object
 * @ipa_obj: IPA object
 *
 * Return: psoc object
 */
static inline struct wlan_objmgr_psoc *
ipa_priv_obj_get_psoc(struct wlan_ipa_priv *ipa_obj)
{
	return ipa_obj->psoc;
}

/**
 * ipa_is_hw_support() - Is IPA HW support?
 *
 * Return: true if IPA HW  is present or false otherwise
 */
bool ipa_is_hw_support(void);

/**
 * ipa_config_mem_alloc() - IPA config allocation
 *
 * Return: QDF_STATUS_SUCCESS on success
 */
QDF_STATUS ipa_config_mem_alloc(void);

/**
 * ipa_config_mem_free() - IPA config mem free
 *
 * Return: None
 */
void ipa_config_mem_free(void);

/**
 * ipa_config_is_enabled() - Is IPA config enabled?
 *
 * Return: true if IPA is enabled in IPA config
 */
bool ipa_config_is_enabled(void);

/**
 * ipa_config_is_uc_enabled() - Is IPA uC config enabled?
 *
 * Return: true if IPA uC is enabled in IPA config
 */
bool ipa_config_is_uc_enabled(void);

/**
 * ipa_config_is_opt_wifi_dp_enabled() - Is IPA optional wifi dp enabled?
 *
 * Return: true if IPA opt wifi dp is enabled in IPA config
 */
bool ipa_config_is_opt_wifi_dp_enabled(void);

/**
 * ipa_config_is_vlan_enabled() - Is IPA vlan config enabled?
 *
 * Return: true if IPA clan support is enabled in IPA config
 */
bool ipa_config_is_vlan_enabled(void);

/**
 * ipa_config_is_two_tx_pipes_enabled - Is IPA two tx pipes feature enabled
 *
 * Return: true if two tx pipes feature is enabled. Otherwise false.
 */
bool ipa_config_is_two_tx_pipes_enabled(void);

/**
 * ipa_obj_setup() - IPA obj initialization and setup
 * @ipa_ctx: IPA obj context
 *
 * Return: QDF_STATUS_SUCCESS on success
 */
QDF_STATUS ipa_obj_setup(struct wlan_ipa_priv *ipa_ctx);

/**
 * ipa_obj_cleanup() - IPA obj cleanup
 * @ipa_ctx: IPA obj context
 *
 * Return: QDF_STATUS_SUCCESS on success
 */
QDF_STATUS ipa_obj_cleanup(struct wlan_ipa_priv *ipa_ctx);

/**
 * ipa_send_uc_offload_enable_disable() - wdi enable/disable notify to fw
 * @psoc: objmgr psoc object
 * @req: ipa offload control request
 *
 * Return: QDF status success or failure
 */
QDF_STATUS ipa_send_uc_offload_enable_disable(struct wlan_objmgr_psoc *psoc,
					      struct ipa_uc_offload_control_params *req);

/**
 * ipa_send_intrabss_enable_disable() - wdi intrabss enable/disable notify to fw
 * @psoc: objmgr psoc object
 * @req: ipa intrabss control request
 *
 * Return: QDF status success or failure
 */
QDF_STATUS
ipa_send_intrabss_enable_disable(struct wlan_objmgr_psoc *psoc,
				 struct ipa_intrabss_control_params *req);

/**
 * ipa_set_dp_handle() - set dp soc handle
 * @psoc: psoc handle
 * @dp_soc: dp soc handle
 *
 * Return: None
 */
void ipa_set_dp_handle(struct wlan_objmgr_psoc *psoc, void *dp_soc);

/**
 * ipa_rm_set_perf_level() - set ipa rm perf level
 * @pdev: pdev handle
 * @tx_packets: packets transmitted in the last sample period
 * @rx_packets: packets received in the last sample period
 *
 * Return: QDF_STATUS
 */
QDF_STATUS ipa_rm_set_perf_level(struct wlan_objmgr_pdev *pdev,
				 uint64_t tx_packets, uint64_t rx_packets);

/**
 * ipa_uc_info() - Print IPA uC resource and session information
 * @pdev: pdev obj
 *
 * Return: None
 */
void ipa_uc_info(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_uc_stat() - Print IPA uC stats
 * @pdev: pdev obj
 *
 * Return: None
 */
void ipa_uc_stat(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_set_opt_dp_ctrl_flt() - flt add for opt_dp_ctrl
 * @pdev: pdev obj
 * @flt: flt params
 *
 * Return: None
 */
void ipa_set_opt_dp_ctrl_flt(struct wlan_objmgr_pdev *pdev,
			     struct ipa_wdi_opt_dpath_flt_add_cb_params *flt);

/*
 * ipa_set_opt_dp_ctrl_flt_rm() - flt del for opt_dp_ctrl
 * @pdev: pdev obj
 * @flt: flt params
 *
 * Return: None
 */
void ipa_set_opt_dp_ctrl_flt_rm(
			struct wlan_objmgr_pdev *pdev,
			struct ipa_wdi_opt_dpath_flt_rem_cb_params *flt);

/**
 * ipa_uc_rt_debug_host_dump() - IPA rt debug host dump
 * @pdev: pdev obj
 *
 * Return: None
 */
void ipa_uc_rt_debug_host_dump(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_dump_info() - Dump IPA context information
 * @pdev: pdev obj
 *
 * Return: None
 */
void ipa_dump_info(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_uc_stat_request() - Get IPA stats from IPA.
 * @pdev: pdev obj
 * @reason: STAT REQ Reason
 *
 * Return: None
 */
void ipa_uc_stat_request(struct wlan_objmgr_pdev *pdev,
			 uint8_t reason);

/**
 * ipa_uc_stat_query() - Query the IPA stats
 * @pdev: pdev obj
 * @ipa_tx_diff: tx packet count diff from previous tx packet count
 * @ipa_rx_diff: rx packet count diff from previous rx packet count
 *
 * Return: None
 */
void ipa_uc_stat_query(struct wlan_objmgr_pdev *pdev,
		       uint32_t *ipa_tx_diff, uint32_t *ipa_rx_diff);

/**
 * ipa_reg_sap_xmit_cb() - Register upper layer SAP cb to transmit
 * @pdev: pdev obj
 * @cb: callback
 *
 * Return: None
 */
void ipa_reg_sap_xmit_cb(struct wlan_objmgr_pdev *pdev,
			 wlan_ipa_softap_xmit cb);

/**
 * ipa_reg_send_to_nw_cb() - Register cb to send IPA Rx packet to network
 * @pdev: pdev obj
 * @cb: callback
 *
 * Return: None
 */
void ipa_reg_send_to_nw_cb(struct wlan_objmgr_pdev *pdev,
			   wlan_ipa_send_to_nw cb);

#if defined(QCA_CONFIG_RPS) && !defined(MDM_PLATFORM)
/**
 * ipa_reg_rps_enable_cb() - Register cb to enable RPS
 * @pdev: pdev obj
 * @cb: callback
 *
 * Return: None
 */
void ipa_reg_rps_enable_cb(struct wlan_objmgr_pdev *pdev,
			   wlan_ipa_rps_enable cb);
#endif

/**
 * ipa_reg_is_driver_unloading_cb() - Register cb to check if driver is
 *                                    unloading
 * @pdev: pdev obj
 * @cb: callback
 *
 * Return: None
 */
void ipa_reg_is_driver_unloading_cb(struct wlan_objmgr_pdev *pdev,
				    wlan_ipa_driver_unloading cb);
/**
 * ipa_set_mcc_mode() - Set MCC mode
 * @pdev: pdev obj
 * @mcc_mode: 0=MCC/1=SCC
 *
 * Return: void
 */
void ipa_set_mcc_mode(struct wlan_objmgr_pdev *pdev, bool mcc_mode);

/**
 * ipa_set_dfs_cac_tx() - Set DFS cac tx block
 * @pdev: pdev obj
 * @tx_block: dfs cac tx block
 *
 * Return: void
 */
void ipa_set_dfs_cac_tx(struct wlan_objmgr_pdev *pdev, bool tx_block);

/**
 * ipa_set_ap_ibss_fwd() - Set AP intra bss forward
 * @pdev: pdev obj
 * @session_id: vdev id
 * @intra_bss: enable or disable ap intra bss forward
 *
 * Return: void
 */
void ipa_set_ap_ibss_fwd(struct wlan_objmgr_pdev *pdev, uint8_t session_id,
			 bool intra_bss);

/**
 * ipa_uc_force_pipe_shutdown() - Force IPA pipe shutdown
 * @pdev: pdev obj
 *
 * Return: void
 */
void ipa_uc_force_pipe_shutdown(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_flush() - flush IPA exception path SKB's
 * @pdev: pdev obj
 *
 * Return: None
 */
void ipa_flush(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_suspend() - Suspend IPA
 * @pdev: pdev obj
 *
 * Return: QDF STATUS
 */
QDF_STATUS ipa_suspend(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_resume() - Resume IPA
 * @pdev: pdev obj
 *
 * Return: None
 */
QDF_STATUS ipa_resume(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_uc_ol_init() - Initialize IPA uC offload
 * @psoc: psoc obj
 * @osdev: OS dev
 *
 * Return: QDF STATUS
 */
QDF_STATUS ipa_uc_ol_init(struct wlan_objmgr_psoc *psoc,
			  qdf_device_t osdev);

/**
 * ipa_uc_ol_deinit() - Deinitialize IPA uC offload
 * @pdev: pdev obj
 *
 * Return: QDF STATUS
 */
QDF_STATUS ipa_uc_ol_deinit(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_is_tx_pending() - Check if IPA WLAN TX completions are pending
 * @pdev: pdev obj
 *
 * Return: bool if pending TX for IPA.
 */
bool ipa_is_tx_pending(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_send_mcc_scc_msg() - Send IPA WLAN_SWITCH_TO_MCC/SCC message
 * @pdev: pdev obj
 * @mcc_mode: 0=MCC/1=SCC
 *
 * Return: QDF STATUS
 */
QDF_STATUS ipa_send_mcc_scc_msg(struct wlan_objmgr_pdev *pdev,
				bool mcc_mode);

/**
 * ipa_wlan_evt() - IPA event handler
 * @pdev: pdev obj
 * @net_dev: Interface net device
 * @device_mode: Net interface device mode
 * @session_id: session id for the event
 * @ipa_event_type: event enum of type ipa_wlan_event
 * @mac_addr: MAC address associated with the event
 * @is_2g_iface: true if interface is operating on 2G band, otherwise false
 *
 * Return: QDF_STATUS
 */
QDF_STATUS ipa_wlan_evt(struct wlan_objmgr_pdev *pdev, qdf_netdev_t net_dev,
			uint8_t device_mode, uint8_t session_id,
			enum wlan_ipa_wlan_event ipa_event_type,
			const uint8_t *mac_addr, bool is_2g_iface);

/**
 * ipa_uc_smmu_map() - Map / Unmap DMA buffer to IPA UC
 * @map: Map / unmap operation
 * @num_buf: Number of buffers in array
 * @buf_arr: Buffer array of DMA mem mapping info
 *
 * Return: Status of map operation
 */
int ipa_uc_smmu_map(bool map, uint32_t num_buf, qdf_mem_info_t *buf_arr);

/**
 * ipa_is_fw_wdi_activated - Is FW WDI activated?
 * @pdev: pdev obj
 *
 * Return: true if FW WDI activated, false otherwise
 */
bool ipa_is_fw_wdi_activated(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_uc_cleanup_sta() - disconnect and cleanup sta iface
 * @pdev: pdev obj
 * @net_dev: Interface net device
 * @session_id: vdev id
 *
 * Send disconnect sta event to IPA driver and cleanup IPA iface,
 * if not yet done
 *
 * Return: void
 */
void ipa_uc_cleanup_sta(struct wlan_objmgr_pdev *pdev,
			qdf_netdev_t net_dev, uint8_t session_id);

/**
 * ipa_uc_disconnect_ap() - send ap disconnect event
 * @pdev: pdev obj
 * @net_dev: Interface net device
 *
 * Send disconnect ap event to IPA driver
 *
 * Return: QDF_STATUS
 */
QDF_STATUS ipa_uc_disconnect_ap(struct wlan_objmgr_pdev *pdev,
				qdf_netdev_t net_dev);

/**
 * ipa_cleanup_dev_iface() - Clean up net dev IPA interface
 * @pdev: pdev obj
 * @net_dev: Interface net device
 * @session_id: vdev_id
 *
 * Return: None
 */
void ipa_cleanup_dev_iface(struct wlan_objmgr_pdev *pdev,
			   qdf_netdev_t net_dev, uint8_t session_id);

/*
 * ipa_uc_shutdown_opt_dp_ctrl_cleanup() - enables flag to clean filters
 * in opt_dp_ctrl
 * @pdev: pdev obj
 *
 * Return: None
 */
void ipa_uc_shutdown_opt_dp_ctrl_cleanup(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_uc_ssr_cleanup() - handle IPA UC cleanup during SSR
 * @pdev: pdev obj
 *
 * Return: None
 */
void ipa_uc_ssr_cleanup(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_fw_rejuvenate_send_msg() - send fw rejuvenate message to IPA driver
 * @pdev: pdev obj
 *
 * Return: None
 */
void ipa_fw_rejuvenate_send_msg(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_component_config_update() - update ipa config from psoc
 * @psoc: psoc obj
 *
 * Return: None
 */
void ipa_component_config_update(struct wlan_objmgr_psoc *psoc);

/**
 * ipa_component_config_free() - Free ipa config
 *
 * Return: None
 */
void ipa_component_config_free(void);

/**
 * ipa_get_tx_buf_count() - get IPA config tx buffer count
 *
 * Return: IPA config tx buffer count
 */
uint32_t ipa_get_tx_buf_count(void);

/**
 * ipa_update_tx_stats() - Update embedded tx traffic in bytes to IPA
 * @pdev: pdev obj
 * @sta_tx: tx in bytes on sta vdev
 * @ap_tx: tx in bytes on sap vdev
 *
 * Return: None
 */
void ipa_update_tx_stats(struct wlan_objmgr_pdev *pdev, uint64_t sta_tx,
			 uint64_t ap_tx);

/**
 * ipa_flush_pending_vdev_events() - flush pending vdev wlan ipa events
 * @pdev: pdev obj
 * @vdev_id: vdev id
 *
 * Return: None
 */
void ipa_flush_pending_vdev_events(struct wlan_objmgr_pdev *pdev,
				   uint8_t vdev_id);

/**
 * ipa_cb_is_ready() - Is IPA register callback is invoked
 *
 * Return: true if IPA register callback is invoked or false
 * otherwise
 */
bool ipa_cb_is_ready(void);

/**
 * ipa_init_deinit_lock() - lock ipa init deinit lock
 *
 * Return: None
 */
void ipa_init_deinit_lock(void);

/**
 * ipa_init_deinit_unlock() - unlock ipa init deinit lock
 *
 * Return: None
 */
void ipa_init_deinit_unlock(void);

/**
 * ipa_is_wds_enabled() - IPA wds status
 *
 * Return: true if WDS is enabled otherwise false
 */
bool ipa_is_wds_enabled(void);

/**
 * ipa_get_alt_pipe() - Get alt_pipe for vdev_id
 * @pdev: pdev obj
 * @vdev_id: vdev_id of the target interface
 * @alt_pipe: Boolean output to indicate if interface with @vdev_id
 *	      is using alternate TX pipe or not.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS ipa_get_alt_pipe(struct wlan_objmgr_pdev *pdev,
			    uint8_t vdev_id,
			    bool *alt_pipe);

/**
 * ipa_set_perf_level_bw_enabled - Get bandwidth based IPA perf voting status
 * @pdev: pdev objmgr pointer
 *
 * This function returns true or false for bandwidth based IPA perf level
 * voting.
 *
 * Return: true - bandwidth based IPA perf voting is enabld. Otherwise false.
 */
bool ipa_set_perf_level_bw_enabled(struct wlan_objmgr_pdev *pdev);

/**
 * ipa_set_perf_level_bw() - Set IPA perf level based on BW
 * @pdev: pdev objmgr pointer
 * @lvl: enum wlan_ipa_bw_level
 *
 * This routine is called to set IPA perf level based on max BW
 * configured among in-use STA and SAP vdevs
 *
 * Return: None
 */
void ipa_set_perf_level_bw(struct wlan_objmgr_pdev *pdev,
			   enum wlan_ipa_bw_level lvl);

#if defined(QCA_IPA_LL_TX_FLOW_CONTROL)
/**
 * ipa_event_wq() - Queue WLAN IPA event for later processing
 * @psoc: psoc handle
 * @peer_mac_addr: peer mac address
 * @vdev: vdev object
 * @wlan_event: wlan event
 *
 * Return: None
 */
void ipa_event_wq(struct wlan_objmgr_psoc *psoc, uint8_t *peer_mac_addr,
		  struct wlan_objmgr_vdev *vdev,
		  enum wlan_ipa_wlan_event wlan_event);

/**
 * wlan_psoc_ipa_evt_wq_attach() - Create WQ to handle IPA event
 * @psoc: psoc handle
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
wlan_psoc_ipa_evt_wq_attach(struct wlan_objmgr_psoc *psoc);

/**
 * wlan_psoc_ipa_evt_wq_detach() - Detach WQ which handle IPA event
 * @psoc: psoc handle
 *
 * Return: None
 */
void wlan_psoc_ipa_evt_wq_detach(struct wlan_objmgr_psoc *psoc);
#endif

#else /* Not IPA_OFFLOAD */
typedef QDF_STATUS (*wlan_ipa_softap_xmit)(qdf_nbuf_t nbuf, qdf_netdev_t dev);
typedef void (*wlan_ipa_send_to_nw)(qdf_nbuf_t nbuf, qdf_netdev_t dev);
typedef void (*wlan_ipa_rps_enable)(uint8_t vdev_id, bool enable);
typedef bool (*wlan_ipa_driver_unloading)(void);

#endif /* IPA_OFFLOAD */
#endif /* end  of _WLAN_IPA_MAIN_H_ */
