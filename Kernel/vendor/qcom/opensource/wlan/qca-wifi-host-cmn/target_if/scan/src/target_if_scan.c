/*
 * Copyright (c) 2017-2021 The Linux Foundation. All rights reserved.
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
 * DOC: offload lmac interface APIs definitions for scan
 */

#include <qdf_mem.h>
#include <qdf_status.h>
#include <target_if_scan.h>
#include <wmi_unified_priv.h>
#include <wmi_unified_param.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_scan_tgt_api.h>
#include <target_if.h>

static inline struct wlan_lmac_if_scan_rx_ops *
target_if_scan_get_rx_ops(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		target_if_err("rx_ops is NULL");
		return NULL;
	}

	return &rx_ops->scan;
}

QDF_STATUS target_if_update_aux_support(struct wlan_objmgr_psoc *psoc)
{
	struct wmi_unified *wmi_handle;
	struct wlan_scan_obj *scan_obj;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);

	if (!wmi_handle) {
		target_if_err("null wmi handle");
		return QDF_STATUS_E_FAILURE;
	}
	scan_obj = wlan_psoc_get_scan_obj(psoc);

	if (!scan_obj) {
		target_if_err("Failed to get scan object");
		return QDF_STATUS_E_FAILURE;
	}
	if (wmi_service_enabled(wmi_handle, wmi_service_aux_mac_support))
		scan_obj->aux_mac_support = true;
	else
		scan_obj->aux_mac_support = false;

	target_if_debug("aux_mac_support:%d", scan_obj->aux_mac_support);
	return QDF_STATUS_SUCCESS;
}

static int
target_if_scan_event_handler(ol_scn_t scn, uint8_t *data, uint32_t datalen)
{
	struct scan_event_info *event_info;
	struct wlan_objmgr_psoc *psoc;
	struct wmi_unified *wmi_handle;
	struct wlan_lmac_if_scan_rx_ops *scan_rx_ops;
	QDF_STATUS status;

	if (!scn || !data) {
		target_if_err("scn: 0x%pK, data: 0x%pK\n", scn, data);
		return -EINVAL;
	}
	psoc = target_if_get_psoc_from_scn_hdl(scn);
	if (!psoc) {
		target_if_err("null psoc\n");
		return -EINVAL;
	}
	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);

	if (!wmi_handle) {
		target_if_err("wmi_handle is NULL");
		return -EINVAL;
	}

	event_info = qdf_mem_malloc(sizeof(*event_info));

	if (!event_info)
		return -ENOMEM;

	if (wmi_extract_vdev_scan_ev_param(wmi_handle, data,
	   &(event_info->event))) {
		target_if_err("Failed to extract wmi scan event");
		qdf_mem_free(event_info);
		return -EINVAL;
	}

	scan_rx_ops = target_if_scan_get_rx_ops(psoc);
	if (!scan_rx_ops) {
		target_if_err("scan_rx_ops is NULL");
		return -EINVAL;
	}

	if (scan_rx_ops->scan_ev_handler) {
		status = scan_rx_ops->scan_ev_handler(psoc, event_info);
		if (status != QDF_STATUS_SUCCESS) {
			qdf_mem_free(event_info);
			return -EINVAL;
		}
	} else {
		qdf_mem_free(event_info);
		return -EINVAL;
	}

	return 0;
}

#ifdef FEATURE_WLAN_SCAN_PNO

int target_if_nlo_complete_handler(ol_scn_t scn, uint8_t *data,
	uint32_t len)
{
	struct scan_event_info *event_info;
	struct wlan_objmgr_psoc *psoc;
	struct wmi_unified *wmi_handle;
	struct wlan_lmac_if_scan_rx_ops *scan_rx_ops;
	QDF_STATUS status;

	if (!scn || !data) {
		target_if_err("scn: 0x%pK, data: 0x%pK", scn, data);
		return -EINVAL;
	}

	psoc = target_if_get_psoc_from_scn_hdl(scn);
	if (!psoc) {
		target_if_err("null psoc");
		return -EINVAL;
	}

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("wmi_handle is NULL");
		return -EINVAL;
	}

	event_info = qdf_mem_malloc(sizeof(*event_info));
	if (!event_info)
		return -ENOMEM;

	if (wmi_extract_nlo_complete_ev_param(wmi_handle, data,
					      &event_info->event)) {
		target_if_err("Failed to extract WMI PNO complete event");
		qdf_mem_free(event_info);
		return -EINVAL;
	}

	target_if_debug("PNO complete event received for vdev %d",
			event_info->event.vdev_id);

	scan_rx_ops = target_if_scan_get_rx_ops(psoc);
	if (!scan_rx_ops) {
		target_if_err("scan_rx_ops is NULL");
		return -EINVAL;
	}

	if (scan_rx_ops->scan_ev_handler) {
		status = scan_rx_ops->scan_ev_handler(psoc, event_info);
		if (status != QDF_STATUS_SUCCESS) {
			qdf_mem_free(event_info);
			return -EINVAL;
		}
	} else {
		qdf_mem_free(event_info);
		return -EINVAL;
	}

	return 0;
}

int target_if_nlo_match_event_handler(ol_scn_t scn, uint8_t *data,
	uint32_t len)
{
	struct scan_event_info *event_info;
	struct wlan_objmgr_psoc *psoc;
	struct wmi_unified *wmi_handle;
	struct wlan_lmac_if_scan_rx_ops *scan_rx_ops;
	QDF_STATUS status;

	if (!scn || !data) {
		target_if_err("scn: 0x%pK, data: 0x%pK", scn, data);
		return -EINVAL;
	}

	psoc = target_if_get_psoc_from_scn_hdl(scn);
	if (!psoc) {
		target_if_err("null psoc");
		return -EINVAL;
	}

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("wmi_handle is NULL");
		return -EINVAL;
	}

	event_info = qdf_mem_malloc(sizeof(*event_info));
	if (!event_info)
		return -ENOMEM;

	if (wmi_extract_nlo_match_ev_param(wmi_handle, data,
					   &event_info->event)) {
		target_if_err("Failed to extract WMI PNO match event");
		qdf_mem_free(event_info);
		return -EINVAL;
	}

	target_if_debug("PNO match event received for vdev %d",
			event_info->event.vdev_id);

	scan_rx_ops = target_if_scan_get_rx_ops(psoc);
	if (!scan_rx_ops) {
		target_if_err("scan_rx_ops is NULL");
		return -EINVAL;
	}

	if (scan_rx_ops->scan_ev_handler) {
		status = scan_rx_ops->scan_ev_handler(psoc, event_info);
		if (status != QDF_STATUS_SUCCESS) {
			qdf_mem_free(event_info);
			return -EINVAL;
		}
	} else {
		qdf_mem_free(event_info);
		return -EINVAL;
	}

	return 0;
}

static QDF_STATUS
target_if_scan_register_pno_event_handler(struct wlan_objmgr_psoc *psoc,
	void *arg)
{
	QDF_STATUS status;
	struct wmi_unified *wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("Invalid WMI handle");
		return QDF_STATUS_E_FAILURE;
	}

	status = wmi_unified_register_event(
			wmi_handle,
			wmi_nlo_match_event_id,
			target_if_nlo_match_event_handler);
	if (status) {
		target_if_err("Failed to register nlo match event cb");
		return QDF_STATUS_E_FAILURE;
	}

	status = wmi_unified_register_event(
			wmi_handle,
			wmi_nlo_scan_complete_event_id,
			target_if_nlo_complete_handler);
	if (status) {
		target_if_err("Failed to register nlo scan comp event cb");
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
target_if_scan_unregister_pno_event_handler(struct wlan_objmgr_psoc *psoc,
		void *arg)
{
	QDF_STATUS status;
	struct wmi_unified *wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("Invalid WMI handle");
		return QDF_STATUS_E_FAILURE;
	}

	status = wmi_unified_unregister_event(
			wmi_handle,
			wmi_nlo_match_event_id);
	if (status) {
		target_if_err("Failed to unregister nlo match event cb");
		return QDF_STATUS_E_FAILURE;
	}

	status = wmi_unified_unregister_event(
			wmi_handle,
			wmi_nlo_scan_complete_event_id);
	if (status) {
		target_if_err("Failed to unregister nlo scan comp event cb");
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
target_if_pno_start(struct wlan_objmgr_psoc *psoc,
	struct pno_scan_req_params *req)
{
	QDF_STATUS status;
	struct wmi_unified *wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("Invalid WMI handle");
		return QDF_STATUS_E_FAILURE;
	}

	status = wmi_unified_pno_start_cmd(wmi_handle, req);
	if (status == QDF_STATUS_SUCCESS) {
		if (req->mawc_params.enable)
			status = wmi_unified_nlo_mawc_cmd(wmi_handle,
							  &req->mawc_params);
	}

	return status;
}

static QDF_STATUS
target_if_pno_stop(struct wlan_objmgr_psoc *psoc,
	uint8_t vdev_id)
{
	struct wmi_unified *wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("Invalid WMI handle");
		return QDF_STATUS_E_FAILURE;
	}

	return wmi_unified_pno_stop_cmd(wmi_handle, vdev_id);
}

#else

static inline QDF_STATUS
target_if_scan_register_pno_event_handler(struct wlan_objmgr_psoc *psoc,
	void *arg)
{
	return QDF_STATUS_SUCCESS;
}

static inline QDF_STATUS
target_if_scan_unregister_pno_event_handler(struct wlan_objmgr_psoc *psoc,
	void *arg)
{
	return QDF_STATUS_SUCCESS;
}

static inline QDF_STATUS
target_if_pno_start(struct wlan_objmgr_psoc *psoc,
	struct pno_scan_req_params *req)
{
	return QDF_STATUS_SUCCESS;
}

static inline QDF_STATUS
target_if_pno_stop(struct wlan_objmgr_psoc *psoc,
	uint8_t vdev_id)
{
	return QDF_STATUS_SUCCESS;
}
#endif

static QDF_STATUS
target_if_obss_scan_disable(struct wlan_objmgr_psoc *psoc,
			    uint8_t vdev_id)
{
	struct wmi_unified *wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("Invalid WMI handle");
		return QDF_STATUS_E_FAILURE;
	}

	return wmi_unified_obss_disable_cmd(wmi_handle, vdev_id);
}

#ifdef FEATURE_WLAN_ZERO_POWER_SCAN
static inline QDF_STATUS
target_if_scan_register_cached_scan_report_handler(wmi_unified_t wmi_handle)
{
	return wmi_unified_register_event(wmi_handle,
					  wmi_scan_cache_result_eventid,
					  target_if_scan_cached_scan_report_handler);
}

static inline QDF_STATUS
target_if_scan_unregister_cached_scan_report_handler(wmi_unified_t wmi_handle)
{
	return wmi_unified_unregister_event(wmi_handle,
					    wmi_scan_cache_result_eventid);
}
#else
static inline QDF_STATUS
target_if_scan_register_cached_scan_report_handler(wmi_unified_t wmi_handle)
{
	return QDF_STATUS_SUCCESS;
}

static inline QDF_STATUS
target_if_scan_unregister_cached_scan_report_handler(wmi_unified_t wmi_handle)
{
	return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS
target_if_scan_register_event_handler(struct wlan_objmgr_psoc *psoc, void *arg)
{
	QDF_STATUS status;
	struct wmi_unified *wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("Invalid WMI handle");
		return QDF_STATUS_E_FAILURE;
	}

	status = wmi_unified_register_event(
			wmi_handle,
			wmi_scan_event_id,
			target_if_scan_event_handler);
	if (status) {
		target_if_err("Failed to register Scan match event cb");
		return QDF_STATUS_E_FAILURE;
	}

	status = target_if_scan_register_pno_event_handler(psoc, arg);
	if (status) {
		target_if_err("Failed to register pno event handler cb");
		return QDF_STATUS_E_FAILURE;
	}

	status = target_if_scan_register_cached_scan_report_handler(wmi_handle);

	return status;
}

QDF_STATUS
target_if_scan_unregister_event_handler(struct wlan_objmgr_psoc *psoc,
		void *arg)
{
	QDF_STATUS status;
	struct wmi_unified *wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		target_if_err("Invalid WMI handle");
		return QDF_STATUS_E_FAILURE;
	}

	status = wmi_unified_unregister_event(
			wmi_handle,
			wmi_scan_event_id);
	if (status) {
		target_if_err("Failed to unregister Scan match event cb");
		return QDF_STATUS_E_FAILURE;
	}

	status = target_if_scan_unregister_pno_event_handler(psoc, arg);
	if (status) {
		target_if_err("Failed to unregister pno event cb");
		return QDF_STATUS_E_FAILURE;
	}

	status = target_if_scan_unregister_cached_scan_report_handler(wmi_handle);
	if (status)
		target_if_err("Failed to unregister cached scan report");

	return status;
}

QDF_STATUS
target_if_scan_start(struct wlan_objmgr_pdev *pdev,
		struct scan_start_request *req)
{
	wmi_unified_t pdev_wmi_handle;

	pdev_wmi_handle = GET_WMI_HDL_FROM_PDEV(pdev);
	if (!pdev_wmi_handle) {
		target_if_err("Invalid PDEV WMI handle");
		return QDF_STATUS_E_FAILURE;
	}
	return wmi_unified_scan_start_cmd_send(pdev_wmi_handle, &req->scan_req);
}

QDF_STATUS
target_if_scan_cancel(struct wlan_objmgr_pdev *pdev,
		struct scan_cancel_param *req)
{
	wmi_unified_t pdev_wmi_handle;

	pdev_wmi_handle = GET_WMI_HDL_FROM_PDEV(pdev);
	if (!pdev_wmi_handle) {
		target_if_err("Invalid PDEV WMI handle");
		return QDF_STATUS_E_NULL_VALUE;
	}
	return wmi_unified_scan_stop_cmd_send(pdev_wmi_handle, req);
}

#if defined(WLAN_FEATURE_11BE) && defined(WLAN_FEATURE_11BE_MLO_MBSSID)
bool target_if_is_platform_eht_capable(struct wlan_objmgr_psoc *psoc,
				       uint8_t pdev_id)
{
	struct wlan_psoc_host_mac_phy_caps *mac_phy_cap_arr, *mac_phy_cap;

	if (psoc->tgt_if_handle) {
		mac_phy_cap_arr =
			target_psoc_get_mac_phy_cap(psoc->tgt_if_handle);
		if (!mac_phy_cap_arr)
			return false;

		mac_phy_cap = &mac_phy_cap_arr[pdev_id];
		if (mac_phy_cap && mac_phy_cap->supports_11be)
			return true;
	}

	return false;
}
#else
bool target_if_is_platform_eht_capable(struct wlan_objmgr_psoc *psoc,
				       uint8_t pdev_id)
{
	return false;
}
#endif

#ifdef FEATURE_WLAN_ZERO_POWER_SCAN
static bool
target_if_scan_get_cached_scan_report_fw_cap(struct wlan_objmgr_pdev *pdev)
{
	struct wmi_unified *wmi_handle;

	wmi_handle = get_wmi_unified_hdl_from_pdev(pdev);
	if (!wmi_handle)
		return false;

	return wmi_service_enabled(wmi_handle,
				   wmi_service_scan_cache_report_support);
}

static inline  void
target_if_register_cached_scan_report_ops(struct wlan_lmac_if_scan_tx_ops *scan)
{
	scan->get_cached_scan_report =
			target_if_scan_request_cached_scan_report;
	scan->get_cached_scan_report_fw_cap =
			target_if_scan_get_cached_scan_report_fw_cap;
}
#else
static inline  void
target_if_register_cached_scan_report_ops(struct wlan_lmac_if_scan_tx_ops *scan)
{
}
#endif

QDF_STATUS
target_if_scan_tx_ops_register(struct wlan_lmac_if_tx_ops *tx_ops)
{
	struct wlan_lmac_if_scan_tx_ops *scan;

	scan = &tx_ops->scan;
	if (!scan) {
		target_if_err("Scan txops NULL");
		return QDF_STATUS_E_FAILURE;
	}

	scan->scan_start = target_if_scan_start;
	scan->scan_cancel = target_if_scan_cancel;
	scan->pno_start = target_if_pno_start;
	scan->pno_stop = target_if_pno_stop;
	scan->obss_disable = target_if_obss_scan_disable;
	scan->scan_reg_ev_handler = target_if_scan_register_event_handler;
	scan->scan_unreg_ev_handler = target_if_scan_unregister_event_handler;
	scan->is_platform_eht_capable = target_if_is_platform_eht_capable;

	target_if_register_cached_scan_report_ops(scan);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
target_if_scan_set_max_active_scans(struct wlan_objmgr_psoc *psoc,
		uint32_t max_active_scans)
{
	struct wlan_lmac_if_scan_rx_ops *scan_rx_ops;
	QDF_STATUS status;

	scan_rx_ops = target_if_scan_get_rx_ops(psoc);
	if (!scan_rx_ops) {
		target_if_err("scan_rx_ops is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	if (scan_rx_ops->scan_set_max_active_scans) {
		status = scan_rx_ops->scan_set_max_active_scans(psoc,
				max_active_scans);
	} else {
		target_if_err("scan_set_max_active_scans uninitialized");
		status = QDF_STATUS_E_FAULT;
	}

	return status;
}
