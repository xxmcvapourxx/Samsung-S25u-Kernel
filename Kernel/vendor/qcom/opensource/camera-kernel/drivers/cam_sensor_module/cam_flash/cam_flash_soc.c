// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/of.h>
#include <linux/of_gpio.h>
#include "cam_flash_soc.h"
#include "cam_res_mgr_api.h"
#include "cam_mem_mgr_api.h"

void cam_flash_put_source_node_data(struct cam_flash_ctrl *fctrl)
{
	uint32_t count = 0, i = 0;
	struct cam_flash_private_soc *soc_private = NULL;

	if (!fctrl) {
		CAM_ERR(CAM_FLASH, "NULL flash control structure");
		return;
	}

	soc_private = fctrl->soc_info.soc_private;

	if (fctrl->switch_trigger) {
		CAM_DBG(CAM_FLASH, "switch trigger: %s",
			soc_private->switch_trigger_name);
		cam_res_mgr_led_trigger_unregister(fctrl->switch_trigger);
	}

	if (fctrl->flash_num_sources) {
		if (fctrl->flash_num_sources > CAM_FLASH_MAX_LED_TRIGGERS) {
			CAM_ERR(CAM_FLASH, "Invalid LED count: %d", count);
			return;
		}

		count = fctrl->flash_num_sources;

		for (i = 0; i < count; i++) {
			CAM_DBG(CAM_FLASH, "Flash default trigger %s",
				soc_private->flash_trigger_name[i]);
			cam_res_mgr_led_trigger_unregister(
				fctrl->flash_trigger[i]);
		}
	}

	if (fctrl->torch_num_sources) {
		if (fctrl->torch_num_sources > CAM_FLASH_MAX_LED_TRIGGERS) {
			CAM_ERR(CAM_FLASH, "Invalid LED count: %d", count);
			return;
		}

		count = fctrl->torch_num_sources;

		for (i = 0; i < count; i++) {
			CAM_DBG(CAM_FLASH, "Flash default trigger %s",
				soc_private->flash_trigger_name[i]);
			cam_res_mgr_led_trigger_unregister(
				fctrl->torch_trigger[i]);
		}
	}
}

#if __or(IS_REACHABLE(CONFIG_LEDS_QPNP_FLASH_V2), \
			IS_REACHABLE(CONFIG_LEDS_QTI_FLASH))
static int32_t cam_get_source_node_info(
	struct device_node *of_node,
	struct cam_flash_ctrl *fctrl,
	struct cam_flash_private_soc *soc_private)
{
	int32_t rc = 0;
	uint32_t count = 0, i = 0;
	struct device_node *flash_src_node = NULL;
	struct device_node *torch_src_node = NULL;
	struct device_node *switch_src_node = NULL;

	soc_private->is_wled_flash =
		of_property_read_bool(of_node, "wled-flash-support");

	switch_src_node = of_parse_phandle(of_node, "switch-source", 0);
	if (!switch_src_node) {
		CAM_WARN(CAM_FLASH, "switch_src_node NULL");
	} else {
		rc = of_property_read_string(switch_src_node,
			"qcom,default-led-trigger",
			&soc_private->switch_trigger_name);
		if (rc) {
			CAM_ERR(CAM_FLASH,
				"default-led-trigger read failed rc=%d", rc);
		} else {
			CAM_DBG(CAM_FLASH, "switch trigger %s",
				soc_private->switch_trigger_name);
			cam_res_mgr_led_trigger_register(
				soc_private->switch_trigger_name,
				&fctrl->switch_trigger);
		}

		of_node_put(switch_src_node);
	}

	if (of_get_property(of_node, "flash-source", &count)) {
		count /= sizeof(uint32_t);

		if (count > CAM_FLASH_MAX_LED_TRIGGERS) {
			CAM_ERR(CAM_FLASH, "Invalid LED count: %d", count);
			return -EINVAL;
		}

		fctrl->flash_num_sources = count;

		for (i = 0; i < count; i++) {
			flash_src_node = of_parse_phandle(of_node,
				"flash-source", i);
			if (!flash_src_node) {
				CAM_WARN(CAM_FLASH, "flash_src_node NULL");
				continue;
			}

			rc = of_property_read_string(flash_src_node,
				"qcom,default-led-trigger",
				&soc_private->flash_trigger_name[i]);
			if (rc) {
				CAM_WARN(CAM_FLASH,
				"defalut-led-trigger read failed rc=%d", rc);
				of_node_put(flash_src_node);
				continue;
			}

			CAM_DBG(CAM_FLASH, "Flash default trigger %s",
				soc_private->flash_trigger_name[i]);
			cam_res_mgr_led_trigger_register(
				soc_private->flash_trigger_name[i],
				&fctrl->flash_trigger[i]);

			if (soc_private->is_wled_flash) {
				rc = cam_flash_led_prepare(
					fctrl->flash_trigger[i],
					QUERY_MAX_AVAIL_CURRENT,
					&soc_private->flash_max_current[i],
					true);
				if (rc) {
					CAM_ERR(CAM_FLASH,
					"WLED FLASH max_current read fail: %d",
						rc);
					of_node_put(flash_src_node);
					rc = 0;
					continue;
				}
			} else {
				rc = of_property_read_u32(flash_src_node,
					"qcom,max-current",
					&soc_private->flash_max_current[i]);
				rc &= of_property_read_u32(flash_src_node,
					"qcom,max-current-ma",
					&soc_private->flash_max_current[i]);
				if (rc < 0) {
					CAM_WARN(CAM_FLASH,
					"LED FLASH max-current read fail: %d",
						rc);
					of_node_put(flash_src_node);
					continue;
				}
			}

			/* Read operational-current */
			if (of_property_read_u32(flash_src_node,
				"qcom,current-ma",
				&soc_private->flash_op_current[i])) {
				CAM_DBG(CAM_FLASH, "op-current: read failed");
			}

			/* Read max-duration */
			rc = of_property_read_u32(flash_src_node,
				"qcom,duration-ms",
				&soc_private->flash_max_duration[i]);
			if (rc) {
				CAM_DBG(CAM_FLASH,
					"max-duration prop unavailable: %d",
					rc);
				rc = 0;
			}
			of_node_put(flash_src_node);

			CAM_DBG(CAM_FLASH, "MainFlashMaxCurrent[%d]: %d",
				i, soc_private->flash_max_current[i]);
		}
	}

	if (of_get_property(of_node, "torch-source", &count)) {
		count /= sizeof(uint32_t);
		if (count > CAM_FLASH_MAX_LED_TRIGGERS) {
			CAM_ERR(CAM_FLASH, "Invalid LED count : %d", count);
			return -EINVAL;
		}

		fctrl->torch_num_sources = count;

		CAM_DBG(CAM_FLASH, "torch_num_sources = %d",
			fctrl->torch_num_sources);
		for (i = 0; i < count; i++) {
			torch_src_node = of_parse_phandle(of_node,
				"torch-source", i);
			if (!torch_src_node) {
				CAM_WARN(CAM_FLASH, "torch_src_node NULL");
				continue;
			}

			rc = of_property_read_string(torch_src_node,
				"qcom,default-led-trigger",
				&soc_private->torch_trigger_name[i]);
			if (rc < 0) {
				CAM_WARN(CAM_FLASH,
					"default-trigger read failed");
				of_node_put(torch_src_node);
				continue;
			}

			CAM_DBG(CAM_FLASH, "Torch default trigger %s",
				soc_private->torch_trigger_name[i]);
			cam_res_mgr_led_trigger_register(
				soc_private->torch_trigger_name[i],
				&fctrl->torch_trigger[i]);

			if (soc_private->is_wled_flash) {
				rc = cam_flash_led_prepare(
					fctrl->torch_trigger[i],
					QUERY_MAX_AVAIL_CURRENT,
					&soc_private->torch_max_current[i],
					true);
				if (rc) {
					CAM_ERR(CAM_FLASH,
					"WLED TORCH max_current read fail: %d",
					rc);
					of_node_put(torch_src_node);
					continue;
				}
			} else {
				rc = of_property_read_u32(torch_src_node,
					"qcom,max-current",
					&soc_private->torch_max_current[i]);
				rc &= of_property_read_u32(torch_src_node,
					"qcom,max-current-ma",
					&soc_private->torch_max_current[i]);
				if (rc < 0) {
					CAM_WARN(CAM_FLASH,
					"LED-TORCH max-current read failed: %d",
						rc);
					of_node_put(torch_src_node);
					continue;
				}
			}

			/* Read operational-current */
			rc = of_property_read_u32(torch_src_node,
				"qcom,current-ma",
				&soc_private->torch_op_current[i]);
			if (rc < 0) {
				CAM_WARN(CAM_FLASH,
					"op-current prop unavailable: %d", rc);
				rc = 0;
			}

			of_node_put(torch_src_node);

			CAM_DBG(CAM_FLASH, "TorchMaxCurrent[%d]: %d",
				i, soc_private->torch_max_current[i]);
		}
	}

	return rc;
}
#endif

int cam_flash_get_dt_data(struct cam_flash_ctrl *fctrl,
	struct cam_hw_soc_info *soc_info)
{
	int32_t rc = 0;
	struct device_node *of_node = NULL;

	if (!fctrl) {
		CAM_ERR(CAM_FLASH, "NULL flash control structure");
		return -EINVAL;
	}

	soc_info->soc_private =
		CAM_MEM_ZALLOC(sizeof(struct cam_flash_private_soc), GFP_KERNEL);
	if (!soc_info->soc_private) {
		rc = -ENOMEM;
		goto release_soc_res;
	}

	if (fctrl->of_node == NULL) {
		CAM_ERR(CAM_FLASH, "device node is NULL");
		rc = -EINVAL;
		goto free_soc_private;
	}

	of_node = fctrl->of_node;

	rc = cam_soc_util_get_dt_properties(soc_info);
	if (rc) {
		CAM_ERR(CAM_FLASH, "Get_dt_properties failed rc %d", rc);
		goto free_soc_private;
	}

#if __or(IS_ENABLED(CONFIG_LEDS_QPNP_FLASH_V2), \
			IS_ENABLED(CONFIG_LEDS_QTI_FLASH))
	rc = cam_get_source_node_info(of_node, fctrl, soc_info->soc_private);
	if (rc) {
		CAM_ERR(CAM_FLASH,
			"cam_flash_get_pmic_source_info failed rc %d", rc);
		goto free_soc_private;
	}
#endif
	return rc;

free_soc_private:
	CAM_MEM_FREE(soc_info->soc_private);
	soc_info->soc_private = NULL;
release_soc_res:
	cam_soc_util_release_platform_resource(soc_info);
	return rc;
}
