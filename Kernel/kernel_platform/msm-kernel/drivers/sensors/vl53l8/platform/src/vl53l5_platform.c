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

#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/version.h>

#include "vl53l5_platform.h"
#include "vl53l5_platform_log.h"
#include "vl53l8_k_logging.h"
#include "vl53l8_k_module_data.h"
#include "vl53l8_k_user_data.h"
#include "vl53l8_k_driver_config.h"
#include "vl53l8_k_gpio_utils.h"
#include "vl53l5_platform_user_data.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#include <stddef.h>
#endif

#define GET_CHUNKS_REQD(size, chunk_size) \
	((size / chunk_size) + ((size % chunk_size) != 0))

#define CURRENT_CHUNK_BYTES(chunk, chunks_reqd, size, chunk_size) \
	(((chunk + 1) * chunk_size) > size ? \
	(size - chunk * chunk_size) : \
	chunk_size)

#define SPI_READWRITE_BIT 0x8000

#define SPI_WRITE_MASK(x) (x | SPI_READWRITE_BIT)
#define SPI_READ_MASK(x)  (x & ~SPI_READWRITE_BIT)

static uint32_t _calculate_twos_complement_uint32(uint32_t value)
{
	uint32_t twos_complement = 0;

	twos_complement = ~value + 0x01;

	return twos_complement;
}

static int platform_spi_write(struct vl53l8_k_module_t *p_module, int index,
				 uint8_t *data, uint16_t len, uint32_t speed_hz)
{
	int status = VL53L5_ERROR_NONE;
	uint8_t index_bytes[2] = {0};
	struct spi_message m;
	struct spi_transfer t[2];

	uint8_t *spi_buffer = NULL;

	spi_message_init(&m);
	memset(&t, 0, sizeof(t));

	if (len > 64) {
		spi_buffer = kzalloc(len, GFP_KERNEL | GFP_DMA);
		if (spi_buffer == NULL) {
			status = -ENOMEM;
			goto out;
		}
		memcpy(spi_buffer, data, len);
	}

	index_bytes[0] = ((SPI_WRITE_MASK(index) & 0xff00) >> 8);
	index_bytes[1] = (SPI_WRITE_MASK(index) & 0xff);

	t[0].tx_buf = index_bytes;
	t[0].len = 2;
	t[0].speed_hz = speed_hz;

	if (len > 64)
		t[1].tx_buf = spi_buffer;
	else
		t[1].tx_buf = data;

	t[1].len = (unsigned int)len;
	t[1].speed_hz = speed_hz;

	spi_message_add_tail(&t[0], &m);
	spi_message_add_tail(&t[1], &m);

	status = spi_sync(p_module->spi_info.device, &m);
	if (status != VL53L5_ERROR_NONE) {
		vl53l8_k_log_error("spi_sync failed. %d\n", status);
		goto out;
	}

out:
	kfree(spi_buffer);
	if (spi_buffer != NULL)
		spi_buffer = NULL;

	return status;
}

static int platform_spi_read(struct vl53l8_k_module_t *module, int index,
			     uint8_t *data, uint16_t len, uint32_t speed_hz)
{
	int status = VL53L5_ERROR_NONE;
	uint8_t index_bytes[2] = {0};
	struct spi_message m;
	struct spi_transfer t[2];

	spi_message_init(&m);
	memset(&t, 0, sizeof(t));

	index_bytes[0] = ((SPI_READ_MASK(index) >> 8) & 0xff);
	index_bytes[1] = (SPI_READ_MASK(index) & 0xff);

	t[0].tx_buf = index_bytes;
	t[0].len = 2;
	t[0].speed_hz = speed_hz;

	t[1].rx_buf = data;
	t[1].len = (unsigned int)len;
	t[1].speed_hz = speed_hz;

	spi_message_add_tail(&t[0], &m);
	spi_message_add_tail(&t[1], &m);

	status = spi_sync(module->spi_info.device, &m);
	if (status != VL53L5_ERROR_NONE) {
		vl53l8_k_log_error("spi_sync failed. %d\n", status);
		goto out;
	}

out:
	return status;
}
#ifdef STM_VL53L8_SUPPORT_LEGACY_CODE
/* Comms close handled by module init and setup. Return 0 */
int32_t vl53l5_comms_initialise(struct vl53l5_dev_handle_t *pdev)
{
	int32_t status = VL53L5_ERROR_NONE;

	(void)pdev;

	return status;
}

/* Comms close handled by module exit and cleanup. Return 0 */
int32_t vl53l5_comms_close(struct vl53l5_dev_handle_t *pdev)
{
	int32_t status = VL53L5_ERROR_NONE;

	(void)pdev;

	return status;
}
#endif
/**
 * Reads the requested number of bytes from the device in multi byte format
 */
int32_t vl53l5_read_multi(struct vl53l5_dev_handle_t *pdev, uint16_t index,
			  uint8_t *pdata, uint32_t count)
{
	int32_t status = 0;
	struct vl53l8_k_module_t *p_module;
	uint16_t chunk_size = 0;
	uint16_t chunks_reqd = 0;
	uint16_t cur_bytes = 0;
	uint16_t offset = 0;
	uint16_t i = 0;
	uint32_t speed_hz = 0;

	p_module = (struct vl53l8_k_module_t *)
		container_of(pdev, struct vl53l8_k_module_t, stdev);

	if (p_module->stdev.host_dev.firmware_load)
		speed_hz = p_module->spi_info.device->max_speed_hz;
	else
		speed_hz = p_module->transfer_speed_hz;

	chunk_size = VL53L8_MAX_SPI_XFER_SZ;

	chunks_reqd = GET_CHUNKS_REQD(count, chunk_size);

	for (i = 0; i < chunks_reqd; i++) {
		cur_bytes = CURRENT_CHUNK_BYTES(i, chunks_reqd, count,
						chunk_size);
		offset = i * chunk_size;
		status = platform_spi_read(p_module, index + offset,
					   pdata + offset, cur_bytes, speed_hz);
		if (status != VL53L5_ERROR_NONE)
			vl53l8_k_log_error("platform_spi_read failure: %d\n",
					   status);
	}

	return status;
}

/**
 * Writes the supplied byte buffer to the device in multi byte format
 */
int32_t vl53l5_write_multi(struct vl53l5_dev_handle_t *pdev, uint16_t index,
			   uint8_t *pdata, uint32_t count)
{
	int32_t status = 0;
	struct vl53l8_k_module_t *p_module;
	uint16_t chunks_reqd = 0;
	uint16_t chunk_size = 0;
	uint16_t cur_bytes = 0;
	uint16_t offset = 0;
	uint16_t i = 0;
	uint32_t speed_hz = 0;

	p_module = (struct vl53l8_k_module_t *)
		container_of(pdev, struct vl53l8_k_module_t, stdev);

	if (p_module->stdev.host_dev.firmware_load)
		speed_hz = p_module->spi_info.device->max_speed_hz;
	else
		speed_hz = p_module->transfer_speed_hz;

	chunk_size = VL53L8_MAX_SPI_XFER_SZ;

	chunks_reqd = GET_CHUNKS_REQD(count, chunk_size);

	for (i = 0; i < chunks_reqd; i++) {
		cur_bytes = CURRENT_CHUNK_BYTES(i, chunks_reqd, count,
						chunk_size);
		offset = i * chunk_size;
		status = platform_spi_write(p_module, index + offset,
					    pdata + offset, cur_bytes,
					    speed_hz);
		if (status != VL53L5_ERROR_NONE)
			vl53l8_k_log_error("platform_spi_write failure: %d\n",
					   status);
	}

	return status;
}

/**
 * Implement a programmable wait in us
 */
int32_t vl53l5_wait_us(struct vl53l5_dev_handle_t *pdev, uint32_t wait_us)
{
	int32_t status = VL53L5_ERROR_NONE;

	/* follow Documentation/timers/timers-howto.txt recommendations */
	if (wait_us < 10)
		udelay(wait_us);
	else if (wait_us < 20000)
		usleep_range(wait_us, wait_us + 1);
	else
		msleep(wait_us / 1000);

	return status;
}

/**
 * Implement a programmable wait in ms
 */
int32_t vl53l5_wait_ms(struct vl53l5_dev_handle_t *pdev, uint32_t wait_ms)
{
	int32_t status = VL53L5_ERROR_NONE;

	status = vl53l5_wait_us(pdev, wait_ms * 1000);

	return status;
}

#ifdef STM_VL53L8_SUPPORT_LEGACY_CODE
/**
 * Sets and clears the low power pin on the VL53L5
 */
int32_t vl53l5_gpio_low_power_control(struct vl53l5_dev_handle_t *pdev,
				      uint8_t value)
{
	int32_t status = VL53L5_ERROR_NONE;
	struct vl53l8_k_module_t *p_module = NULL;

	LOG_FUNCTION_START("");

	p_module = (struct vl53l8_k_module_t *)
		container_of(pdev, struct vl53l8_k_module_t, stdev);

	/* turn on power */
	vl53l8_k_log_debug("Setting gpio low power (%d) to %d\n",
			   p_module->gpio.low_power, value);
	status = vl53l8_k_set_gpio(&p_module->gpio.low_power, value);

	LOG_FUNCTION_END(status);
	return status;
}

/**
 * Enables and disables the power of the platform
 */
int32_t vl53l5_gpio_power_enable(struct vl53l5_dev_handle_t *pdev,
				 uint8_t value)
{
	int32_t status = VL53L5_ERROR_NONE;
	struct vl53l8_k_module_t *p_module = NULL;

	LOG_FUNCTION_START("");

	p_module = (struct vl53l8_k_module_t *)
		container_of(pdev, struct vl53l8_k_module_t, stdev);

	/* turn on power */
	vl53l8_k_log_debug("Setting gpio power enable (%d) to %d\n",
			   p_module->gpio.power_enable, value);
	status = vl53l8_k_set_gpio(&p_module->gpio.power_enable, value);

	LOG_FUNCTION_END(status);
	return status;
}

/**
 * Enables and disables the power of the platform.
 * In this implementation, value is tokenistic. The actual value is obtained
 * from the module struct.
 */
int32_t vl53l5_gpio_comms_select(struct vl53l5_dev_handle_t *pdev,
				 uint8_t value)
{
	int32_t status = VL53L5_ERROR_NONE;
	struct vl53l8_k_module_t *p_module = NULL;

	LOG_FUNCTION_START("");

	p_module = (struct vl53l8_k_module_t *)
		container_of(pdev, struct vl53l8_k_module_t, stdev);

	/* select comms */
	vl53l8_k_log_debug("Setting gpio comms select (%d) to %d\n",
			   p_module->gpio.comms_select, p_module->comms_type);
	status = vl53l8_k_set_gpio(&p_module->gpio.comms_select,
				 p_module->comms_type);

	LOG_FUNCTION_END(status);
	return status;
}
#endif

/*
 * Gets current system tick count in [ms]
 */
int32_t vl53l5_get_tick_count(
	struct vl53l5_dev_handle_t *pdev, uint32_t *ptime_ms)
{
	*ptime_ms = jiffies_to_msecs(jiffies);
	return 0;
}

/*
 * Evaluates a timeout condition based on two tick counts and a timeout value
 * [all in ms]. Accounts for possible timer overflow.
 */
int32_t vl53l5_check_for_timeout(
	struct vl53l5_dev_handle_t *pdev, uint32_t start_time_ms,
	uint32_t end_time_ms, uint32_t timeout_ms)
{
	int32_t status = VL53L5_ERROR_NONE;
	uint32_t time_diff_ms;

	if (start_time_ms <= end_time_ms) {
		time_diff_ms = end_time_ms - start_time_ms;
	} else {
		time_diff_ms = _calculate_twos_complement_uint32(start_time_ms)
			       + end_time_ms;
	}
	if (time_diff_ms > timeout_ms)
		status = VL53L5_ERROR_TIME_OUT;

	return status;
}
#ifdef STM_VL53L8_SUPPORT_LEGACY_CODE
int32_t vl53l5_read_file(struct vl53l5_dev_handle_t *pdev, char *data,
			  int size, const char *path)
{
	int32_t status = VL53L5_ERROR_NONE;
	loff_t offset = 0;
	struct file *filp;

	filp = filp_open(path, O_RDONLY, 0664);
	if (IS_ERR(filp)) {
		status = PTR_ERR(filp);
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	status = kernel_read(filp, data, size, &offset);
#else
	status = kernel_read(filp, offset, data, size);
#endif
	if (status > VL53L5_ERROR_NONE) {
		vl53l8_k_log_debug("Size of data read: %i", status);
		status = VL53L5_ERROR_NONE;
	}

	filp_close(filp, NULL);
out:
	return status;
}

int32_t vl53l5_write_file(struct vl53l5_dev_handle_t *pdev, char *data,
			  int size, const char *path, char *device_info,
			  int info_size)
{
	int32_t status = VL53L5_ERROR_NONE;
	loff_t offset = 0;
	struct file *filp;

	filp = filp_open(path, O_WRONLY|O_CREAT, 0664);
	if (IS_ERR(filp)) {
		status = PTR_ERR(filp);
		goto out;
	}

	if (device_info != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
		status = kernel_write(filp, device_info, info_size, &offset);
#else
		status = kernel_write(filp, device_info, info_size, offset);
#endif
		if (status > VL53L5_ERROR_NONE) {
			vl53l8_k_log_debug("Size of data written: %i", status);
			status = VL53L5_ERROR_NONE;
		}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,14,0)
		offset += info_size;
#endif
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	status = kernel_write(filp, data, size, &offset);
#else
	status = kernel_write(filp, data, size, offset);
#endif
	if (status > VL53L5_ERROR_NONE) {
		vl53l8_k_log_debug("Size of data written: %i", status);
		status = VL53L5_ERROR_NONE;
	}

	filp_close(filp, NULL);
out:
	return status;
}
#endif // STM_VL53L8_SUPPORT_LEGACY_CODE
