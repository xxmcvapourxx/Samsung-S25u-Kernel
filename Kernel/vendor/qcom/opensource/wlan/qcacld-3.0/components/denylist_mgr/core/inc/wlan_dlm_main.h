/*
 * Copyright (c) 2019-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022,2024 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: declare internal APIs related to the denylist manager component
 */

#ifndef _WLAN_DLM_MAIN_H_
#define _WLAN_DLM_MAIN_H_

#include <qdf_time.h>
#include <wlan_objmgr_cmn.h>
#include <wlan_objmgr_global_obj.h>
#include <wlan_dlm_ucfg_api.h>

#define dlm_fatal(params...)\
		QDF_TRACE_FATAL(QDF_MODULE_ID_DENYLIST_MGR, params)
#define dlm_err(params...)\
		QDF_TRACE_ERROR(QDF_MODULE_ID_DENYLIST_MGR, params)
#define dlm_warn(params...)\
		QDF_TRACE_WARN(QDF_MODULE_ID_DENYLIST_MGR, params)
#define dlm_info(params...)\
		QDF_TRACE_INFO(QDF_MODULE_ID_DENYLIST_MGR, params)
#define dlm_debug(params...)\
		QDF_TRACE_DEBUG(QDF_MODULE_ID_DENYLIST_MGR, params)
#define dlm_nofl_debug(params...)\
		QDF_TRACE_DEBUG_NO_FL(QDF_MODULE_ID_DENYLIST_MGR, params)

/**
 * struct dlm_pdev_priv_obj - Pdev priv struct to store list of denylist mgr.
 * @reject_ap_list_lock: Mutex needed to restrict two threads updating the list.
 * @reject_ap_list: The reject Ap list which would contain the list of bad APs.
 * @dlm_tx_ops: tx ops to send reject ap list to FW
 */
struct dlm_pdev_priv_obj {
	qdf_mutex_t reject_ap_list_lock;
	qdf_list_t reject_ap_list;
	struct wlan_dlm_tx_ops dlm_tx_ops;
};

/**
 * struct dlm_config - Structure to define the config params for denylist mgr.
 * @avoid_list_exipry_time: Timer after which transition from avoid->monitor
 * would happen for the BSSID which is in avoid list.
 * @deny_list_exipry_time: Timer after which transition from deny->monitor
 * would happen for the BSSID which is in deny list.
 * @bad_bssid_counter_reset_time: Timer after which the bssid would be removed
 * from the reject list when connected, and data stall is not seen with the AP.
 * @monitor_con_stability_time: Timer for which connection stability needs to
 * be monitored.
 * @bad_bssid_counter_thresh: This is the threshold count which is incremented
 * after every NUD fail, and after this much count, the BSSID would be moved to
 * denylist.
 * @delta_rssi: This is the rssi threshold, only when rssi
 * improves by this value the entry for BSSID should be removed from deny
 * list manager list.
 * @max_11be_con_failure_allowed: Maximum allowed 11BE failures per MLO AP.
 */
struct dlm_config {
	qdf_time_t avoid_list_exipry_time;
	qdf_time_t deny_list_exipry_time;
	qdf_time_t bad_bssid_counter_reset_time;
	qdf_time_t monitor_con_stability_time;
	uint8_t bad_bssid_counter_thresh;
	uint32_t delta_rssi;
#ifdef WLAN_FEATURE_11BE_MLO
	uint8_t max_11be_con_failure_allowed;
#endif
};

/**
 * struct dlm_psoc_priv_obj - Psoc priv structure of the denylist manager.
 * @pdev_id: pdev id
 * @is_suspended: is deny list manager state suspended
 * @dlm_cfg: These are the config ini params that the user can configure.
 */
struct dlm_psoc_priv_obj {
	uint8_t pdev_id;
	bool is_suspended;
	struct dlm_config dlm_cfg;
};

/**
 * dlm_pdev_object_created_notification() - denylist mgr pdev create
 * handler
 * @pdev: pdev which is going to be created by objmgr
 * @arg: argument for pdev create handler
 *
 * Register this api with objmgr to detect if pdev is created.
 *
 * Return: QDF_STATUS status in case of success else return error
 */
QDF_STATUS
dlm_pdev_object_created_notification(struct wlan_objmgr_pdev *pdev,
				     void *arg);

/**
 * dlm_pdev_object_destroyed_notification() - denylist mgr pdev delete handler
 * @pdev: pdev which is going to be deleted by objmgr
 * @arg: argument for pdev delete handler
 *
 * Register this api with objmgr to detect if pdev is deleted.
 *
 * Return: QDF_STATUS status in case of success else return error
 */
QDF_STATUS
dlm_pdev_object_destroyed_notification(struct wlan_objmgr_pdev *pdev,
				       void *arg);

/**
 * dlm_psoc_object_created_notification() - denylist mgr psoc create handler
 * @psoc: psoc which is going to be created by objmgr
 * @arg: argument for psoc create handler
 *
 * Register this api with objmgr to detect if psoc is created.
 *
 * Return: QDF_STATUS status in case of success else return error
 */
QDF_STATUS
dlm_psoc_object_created_notification(struct wlan_objmgr_psoc *psoc,
				     void *arg);

/**
 * dlm_psoc_object_destroyed_notification() - denylist mgr psoc delete handler
 * @psoc: psoc which is going to be deleted by objmgr
 * @arg: argument for psoc delete handler.
 *
 * Register this api with objmgr to detect if psoc is deleted.
 *
 * Return: QDF_STATUS status in case of success else return error
 */
QDF_STATUS
dlm_psoc_object_destroyed_notification(struct wlan_objmgr_psoc *psoc,
				       void *arg);

/**
 * dlm_cfg_psoc_open() - denylist mgr psoc open handler
 * @psoc: psoc which is initialized by objmgr
 *
 * This API will initialize the config file, and store the config while in the
 * psoc priv object of the denylist manager.
 *
 * Return: QDF_STATUS status in case of success else return error
 */
QDF_STATUS
dlm_cfg_psoc_open(struct wlan_objmgr_psoc *psoc);

/**
 * dlm_get_pdev_obj() - Get the pdev priv object of the denylist manager
 * @pdev: pdev object
 *
 * Get the pdev priv object of the denylist manager
 *
 * Return: Pdev priv object if present, else NULL.
 */
struct dlm_pdev_priv_obj *
dlm_get_pdev_obj(struct wlan_objmgr_pdev *pdev);

/**
 * dlm_get_psoc_obj() - Get the psoc priv object of the denylist manager
 * @psoc: psoc object
 *
 * Get the psoc priv object of the denylist manager
 *
 * Return: Psoc priv object if present, else NULL.
 */
struct dlm_psoc_priv_obj *
dlm_get_psoc_obj(struct wlan_objmgr_psoc *psoc);

#endif
