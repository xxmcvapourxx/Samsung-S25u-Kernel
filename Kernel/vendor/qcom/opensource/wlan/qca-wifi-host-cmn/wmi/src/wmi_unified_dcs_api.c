/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: Implement API's specific to DCS component.
 */
#include <wmi_unified_dcs_api.h>

QDF_STATUS wmi_extract_dcs_interference_type(
		void *wmi_hdl,
		void *evt_buf,
		struct wlan_host_dcs_interference_param *param)
{
	wmi_unified_t wmi = (wmi_unified_t)wmi_hdl;

	if (wmi->ops->extract_dcs_interference_type) {
		return wmi->ops->extract_dcs_interference_type(wmi,
							       evt_buf,
							       param);
	}
	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS wmi_extract_dcs_im_tgt_stats(
		void *wmi_hdl,
		void *evt_buf,
		struct wlan_host_dcs_im_tgt_stats *wlan_stat)
{
	wmi_unified_t wmi_handle = (wmi_unified_t)wmi_hdl;

	if (wmi_handle->ops->extract_dcs_im_tgt_stats) {
		return wmi_handle->ops->extract_dcs_im_tgt_stats(wmi_handle,
								 evt_buf,
								 wlan_stat);
	}
	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS wmi_extract_dcs_awgn_info(wmi_unified_t wmi_hdl, void *evt_buf,
				     struct wlan_host_dcs_awgn_info *awgn_info)
{
	if (wmi_hdl && wmi_hdl->ops->extract_dcs_awgn_info)
		return wmi_hdl->ops->extract_dcs_awgn_info(wmi_hdl, evt_buf,
							   awgn_info);

	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS wmi_send_dcs_pdev_param(wmi_unified_t wmi_handle,
				   uint32_t pdev_idx,
				   bool is_host_pdev_id,
				   uint32_t dcs_enable)
{
	struct pdev_params pparam;

	qdf_mem_zero(&pparam, sizeof(pparam));
	pparam.is_host_pdev_id = is_host_pdev_id;
	pparam.param_id = wmi_pdev_param_dcs;
	pparam.param_value = dcs_enable;

	return wmi_unified_pdev_param_send(wmi_handle, &pparam, pdev_idx);
}

#ifdef WLAN_FEATURE_VDEV_DCS
QDF_STATUS wmi_send_dcs_vdev_param(wmi_unified_t wmi_handle,
				   uint8_t vdev_id,
				   uint32_t dcs_enable)
{
	struct vdev_set_params param;

	qdf_mem_zero(&param, sizeof(param));
	param.vdev_id = vdev_id;
	param.param_id = wmi_vdev_param_dcs;
	param.param_value = dcs_enable;

	return wmi_unified_vdev_set_param_send(wmi_handle, &param);
}
#endif
