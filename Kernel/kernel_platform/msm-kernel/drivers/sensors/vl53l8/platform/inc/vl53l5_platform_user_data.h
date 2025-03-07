/*******************************************************************************
* Copyright (c) 2022, STMicroelectronics - All Rights Reserved
*
* This file is part of VL53L8 Kernel Driver and is dual licensed,
* either 'STMicroelectronics Proprietary license'
* or 'BSD 3-clause "New" or "Revised" License' , at your option.
*
********************************************************************************
*
* 'STMicroelectronics Proprietary license'
*
********************************************************************************
*
* License terms: STMicroelectronics Proprietary in accordance with licensing
* terms at www.st.com/sla0081
*
* STMicroelectronics confidential
* Reproduction and Communication of this document is strictly prohibited unless
* specifically authorized in writing by STMicroelectronics.
*
*
********************************************************************************
*
* Alternatively, VL53L8 Kernel Driver may be distributed under the terms of
* 'BSD 3-clause "New" or "Revised" License', in which case the following
* provisions apply instead of the ones mentioned above :
*
********************************************************************************
*
* License terms: BSD 3-clause "New" or "Revised" License.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
*
* 3. Neither the name of the copyright holder nor the names of its contributors
* may be used to endorse or promote products derived from this software
* without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*
*******************************************************************************/


#ifndef _VL53L5_PLATFORM_USER_DATA_H_
#define _VL53L5_PLATFORM_USER_DATA_H_

#include "vl53l5_device.h"

#ifdef __cplusplus
extern "C"
{
#endif

/** @addtogroup VL53L5_platform_group
 *  @{
 */


/** @brief  VL53L5 range data struct
 */
struct vl53l5_range_data_t {
#ifdef VL53L5_RESULTS_DATA_ENABLED
	/** MANDATORY: Range data information required throughout
	 *             VL53L5 driver. Platform independent.
	 */
	struct vl53l5_range_results_t core;
#endif
#ifdef VL53L5_PATCH_DATA_ENABLED
	/** MANDATORY: Range data information required throughout
	 *             VL53L5 driver. Platform independent.
	 */
	struct vl53l5_tcpm_patch_0_results_dev_t tcpm_0_patch;
#endif
};

/**
 * MANDATORY if required calibration decode
 * Platform independent.
 */
#ifdef VL53L5_CALIBRATION_DECODE_ON
struct vl53l5_calibration_data_t {
	struct vl53l5_calibration_dev_t core;
};
#endif

/** @brief  VL53L5 device handle struct
 */
struct vl53l5_dev_handle_t {
	/** MANDATORY: Internal dev handle information required throughout
	 *             VL53L5 driver. Platform independent.
	 */
	struct vl53l5_dev_handle_internal_t host_dev;
#ifdef SS_SUPPORT_SEC_CODE
		int32_t status_using;
		int32_t last_dev_error;

		int8_t status_probe; // 1: probed, others: error code
		int8_t status_cal;	 // 0: no error, others: error code
#endif // SS_SUPPORT_SEC_CODE
};
/** @} vl53l5_platform_group */

#ifdef __cplusplus
}
#endif

#endif
