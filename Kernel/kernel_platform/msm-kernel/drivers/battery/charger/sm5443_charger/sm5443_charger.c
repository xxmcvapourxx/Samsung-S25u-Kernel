/*
 * sm5443_charger.c - SM5443 Charger device driver for SAMSUNG platform
 *
 * Copyright (C) 2023 SiliconMitus Co.Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/power_supply.h>
#if defined(CONFIG_OF)
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/pinctrl/consumer.h>
#include <linux/pm_runtime.h>
#endif /* CONFIG_OF */
#if IS_ENABLED(CONFIG_BATTERY_SAMSUNG)
#include "../../common/sec_charging_common.h"
#include "../../common/sec_direct_charger.h"
#endif
#include "sm5443_charger.h"
#if IS_ENABLED(CONFIG_SEC_ABC)
#include <linux/sti/abc_common.h>
#endif

#define SM5443_DC_VERSION  "XK6"

static int sm5443_read_reg(struct sm5443_charger *sm5443, u8 reg, u8 *dest)
{
	int cnt, ret;
	struct i2c_client *i2c_client;

	/* hid register range */
	if (reg >= SM5443_REG_MSKDEG_OP && reg <= SM5443_REG_PH1_DT_QH1)
		i2c_client = sm5443->i2c_hid;
	else
		i2c_client = sm5443->i2c;

	for (cnt = 0; cnt < 3; ++cnt) {
		ret = i2c_smbus_read_byte_data(i2c_client, reg);
		if (ret < 0)
			dev_err(sm5443->dev, "%s: fail to i2c_read(ret=%d)\n", __func__, ret);
		else
			break;

		if (cnt == 0)
			msleep(30);
	}

	if (ret < 0) {
#if IS_ENABLED(CONFIG_SEC_ABC) && !defined(CONFIG_SEC_FACTORY)
		if (sm5443->valid_ic)
			sec_abc_send_event("MODULE=battery@WARN=dc_i2c_fail");
#endif
		return ret;
	}
	*dest = (ret & 0xff);

	return 0;
}

int sm5443_bulk_read(struct sm5443_charger *sm5443, u8 reg, int count, u8 *buf)
{
	int cnt, ret;

	for (cnt = 0; cnt < 3; ++cnt) {
		ret = i2c_smbus_read_i2c_block_data(sm5443->i2c, reg, count, buf);
		if (ret < 0)
			dev_err(sm5443->dev, "%s: fail to i2c_bulk_read(ret=%d)\n", __func__, ret);
		else
			break;

		if (cnt == 0)
			msleep(30);
	}

#if IS_ENABLED(CONFIG_SEC_ABC) && !defined(CONFIG_SEC_FACTORY)
	if (ret < 0)
		if (sm5443->valid_ic)
			sec_abc_send_event("MODULE=battery@WARN=dc_i2c_fail");
#endif

	return ret;
}

static int sm5443_write_reg(struct sm5443_charger *sm5443, u8 reg, u8 value)
{
	int cnt, ret;
	struct i2c_client *i2c_client;

	/* hid register range */
	if (reg >= SM5443_REG_MSKDEG_OP && reg <= SM5443_REG_PH1_DT_QH1)
		i2c_client = sm5443->i2c_hid;
	else
		i2c_client = sm5443->i2c;

	for (cnt = 0; cnt < 3; ++cnt) {
		ret = i2c_smbus_write_byte_data(i2c_client, reg, value);
		if (ret < 0)
			dev_err(sm5443->dev, "%s: fail to i2c_write(ret=%d)\n", __func__, ret);
		else
			break;

		if (cnt == 0)
			msleep(30);
	}

#if IS_ENABLED(CONFIG_SEC_ABC) && !defined(CONFIG_SEC_FACTORY)
	if (ret < 0)
		if (sm5443->valid_ic)
			sec_abc_send_event("MODULE=battery@WARN=dc_i2c_fail");
#endif

	return ret;
}

static int sm5443_update_reg(struct sm5443_charger *sm5443, u8 reg,
								u8 val, u8 mask, u8 pos)
{
	int ret;
	u8 old_val;

	mutex_lock(&sm5443->i2c_lock);

	ret = sm5443_read_reg(sm5443, reg, &old_val);
	if (ret == 0) {
		u8 new_val = (val & mask) << pos | (old_val & ~(mask << pos));

		ret = sm5443_write_reg(sm5443, reg, new_val);
	}

	mutex_unlock(&sm5443->i2c_lock);

	return ret;
}

static int sm5443_get_flag_irq(struct sm5443_charger *sm5443, u8 *flag1_s, u8 *flag2_s, u8 *flag3_s,
		u8 *flag4_s, u8 *flag5_s, u8 *flag6_s, u8 *flag7_s)
{
	u8 flag1, flag2, flag3, flag4, flag5, flag6, flag7;

	mutex_lock(&sm5443->i2c_lock);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG1, &flag1);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG2, &flag2);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG3, &flag3);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG4, &flag4);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG5, &flag5);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG6, &flag6);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG7, &flag7);
	dev_info(sm5443->dev, "%s: FLAG:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x\n",
		__func__, flag1, flag2, flag3, flag4, flag5, flag6, flag7);
	mutex_unlock(&sm5443->i2c_lock);
	if (flag1_s)
		*flag1_s = flag1;
	if (flag2_s)
		*flag2_s = flag2;
	if (flag3_s)
		*flag3_s = flag3;
	if (flag4_s)
		*flag4_s = flag4;
	if (flag5_s)
		*flag5_s = flag5;
	if (flag6_s)
		*flag6_s = flag6;
	if (flag7_s)
		*flag7_s = flag7;
	return 0;
}

static int sm5443_get_flag_status(struct sm5443_charger *sm5443, u8 *flag1_s, u8 *flag2_s, u8 *flag3_s,
		u8 *flag4_s, u8 *flag5_s, u8 *flag6_s, u8 *flag7_s)
{
	u8 flag1, flag2, flag3, flag4, flag5, flag6, flag7;

	/* read twice to get correct value */
	mutex_lock(&sm5443->i2c_lock);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG1, &flag1);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG2, &flag2);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG3, &flag3);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG4, &flag4);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG5, &flag5);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG6, &flag6);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG7, &flag7);

	sm5443_read_reg(sm5443, SM5443_REG_FLAG1, &flag1);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG2, &flag2);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG3, &flag3);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG4, &flag4);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG5, &flag5);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG6, &flag6);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG7, &flag7);
	dev_info(sm5443->dev, "%s: FLAG:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x\n",
		__func__, flag1, flag2, flag3, flag4, flag5, flag6, flag7);
	mutex_unlock(&sm5443->i2c_lock);

	if (flag1_s)
		*flag1_s = flag1;

	if (flag2_s)
		*flag2_s = flag2;

	if (flag3_s)
		*flag3_s = flag3;

	if (flag4_s)
		*flag4_s = flag4;

	if (flag5_s)
		*flag5_s = flag5;

	if (flag6_s)
		*flag6_s = flag6;

	if (flag7_s)
		*flag7_s = flag7;

	return 0;
}

static u32 sm5443_get_vbatreg(struct sm5443_charger *sm5443)
{
	u8 reg;
	u32 vbatovp, offset;

	sm5443_read_reg(sm5443, SM5443_REG_VBAT_OVP, &reg);
	vbatovp = 4000 + ((reg & 0x7F) * 5);
	sm5443_read_reg(sm5443, SM5443_REG_REG1, &reg);
	offset = ((reg & 0x3) * 50) + 50;

	dev_info(sm5443->dev, "%s: vbatovp=%d, offset=%d\n",
		__func__, vbatovp, offset);

	return (vbatovp - offset);
}

static int sm5443_set_vbatreg(struct sm5443_charger *sm5443, u32 vbatreg)
{
	u8 reg;
	u32 vbatovp, offset;

	sm5443_read_reg(sm5443, SM5443_REG_REG1, &reg);
	offset = ((reg & 0x3) * 50) + 50;
	vbatovp = vbatreg + offset;
	if (vbatovp > 4600)
		vbatovp = 4600;
	if (vbatovp < 4000)
		vbatovp = 4000;

	reg = (vbatovp - 4000) / 5;

	dev_info(sm5443->dev, "%s: vbatovp=%d, offset=%d reg=0x%x\n",
		__func__, vbatovp, offset, reg);

	return sm5443_update_reg(sm5443, SM5443_REG_VBAT_OVP, reg, 0x7F, 0);
}

static u32 sm5443_get_ibuslim(struct sm5443_charger *sm5443)
{
	u8 reg;
	u32 ibusocp, offset;

	sm5443_read_reg(sm5443, SM5443_REG_IBUS_OCP, &reg);
	ibusocp = 500 + ((reg & 0x7F) * 50);
	sm5443_read_reg(sm5443, SM5443_REG_CNTL5, &reg);
	offset = ((reg & 0x7) * 100) + 100;

	dev_info(sm5443->dev, "%s: ibusocp=%d, offset=%d\n",
		__func__, ibusocp, offset);

	return ibusocp - offset;
}

static int sm5443_set_ibuslim(struct sm5443_charger *sm5443, u32 ibuslim)
{
	u8 reg;
	u32 ibusocp, offset;

	sm5443_read_reg(sm5443, SM5443_REG_CNTL5, &reg);
	offset = ((reg & 0x7) * 100) + 100;
	ibusocp = ibuslim + offset;
	if (ibusocp > 6000)
		ibusocp = 6000;
	reg = (ibusocp - 500) / 50;

	dev_info(sm5443->dev, "%s: ibusocp=%d, offset=%d reg=0x%x\n",
		__func__, ibusocp, offset, reg);

	return sm5443_update_reg(sm5443, SM5443_REG_IBUS_OCP, reg, 0x7F, 0);
}

static int sm5443_set_freq(struct sm5443_charger *sm5443, u32 freq)
{
	u8 reg = ((freq - 200) / 100) & 0xF;

	return sm5443_update_reg(sm5443, SM5443_REG_CNTL2, reg, 0xF, 4);
}

static int sm5443_get_freq(struct sm5443_charger *sm5443)
{
	u8 reg;
	u32 freq;

	sm5443_read_reg(sm5443, SM5443_REG_CNTL2, &reg);
	freq = (reg >> 4 & 0xf) * 100 + 200;

	dev_info(sm5443->dev, "%s: freq=%d\n", __func__, freq);

	return freq;
}

static int sm5443_set_op_mode(struct sm5443_charger *sm5443, u8 op_mode)
{
	u8 reg, verify_reg, i;

	if (sm5443->ibusocp) {
		sm5443_update_reg(sm5443, SM5443_REG_DG_TIMER_2, 0x2, 0x3, 6);
		dev_info(sm5443->dev, "%s: ibusocp_dg=2ms\n", __func__);
		sm5443->ibusocp = 0;
	}

	if (sm5443->pdata->rev_id < 1) {
		if (op_mode == OP_MODE_FW_BOOST || op_mode == OP_MODE_FW_3TO1) {
			sm5443_write_reg(sm5443, SM5443_REG_HID_MODE, 0xA5);
			sm5443_write_reg(sm5443, SM5443_REG_HID_MODE, 0x5A);
			sm5443_write_reg(sm5443, SM5443_REG_MSKDEG_OP, 0x18);
			sm5443_write_reg(sm5443, SM5443_REG_PH2_DT_QH2, 0xC0);
			sm5443_write_reg(sm5443, SM5443_REG_PH1_DT_QH1, 0xC0);
			usleep_range(1000, 2000);
			sm5443_write_reg(sm5443, SM5443_REG_HID_MODE, 0x0);

		} else if (op_mode == OP_MODE_REV_BOOST || op_mode == OP_MODE_REV_1TO3) {
			sm5443_write_reg(sm5443, SM5443_REG_HID_MODE, 0xA5);
			sm5443_write_reg(sm5443, SM5443_REG_HID_MODE, 0x5A);
			sm5443_write_reg(sm5443, SM5443_REG_MSKDEG_OP, 0x0);
			sm5443_write_reg(sm5443, SM5443_REG_PH2_DT_QH2, 0x0);
			sm5443_write_reg(sm5443, SM5443_REG_PH1_DT_QH1, 0x0);
			usleep_range(1000, 2000);
			sm5443_write_reg(sm5443, SM5443_REG_HID_MODE, 0x0);
		}
	} else {
		for (i = 0; i < 3; ++i) {
			if (op_mode == OP_MODE_INIT)
				break;
			sm5443_write_reg(sm5443, SM5443_REG_HID_MODE, 0xA5);
			sm5443_write_reg(sm5443, SM5443_REG_HID_MODE, 0x5A);
			usleep_range(1000, 2000);
			reg = (op_mode == OP_MODE_FW_BOOST || op_mode == OP_MODE_REV_BOOST) ? 0x0 : 0x18;
			sm5443_write_reg(sm5443, SM5443_REG_MSKDEG_OP, reg);
			usleep_range(1000, 2000);
			sm5443_write_reg(sm5443, SM5443_REG_HID_MODE, 0x0);
			/* Verify reg */
			sm5443_read_reg(sm5443, SM5443_REG_MSKDEG_OP, &verify_reg);
			if (verify_reg != reg) {
				dev_info(sm5443->dev, "%s: fail to change overlap time[0x%x]\n", __func__, verify_reg);
			} else {
				if (verify_reg == 0x0)
					dev_info(sm5443->dev, "%s: overlap time[0x%x] disable\n", __func__, verify_reg);
				else if (verify_reg == 0x18)
					dev_info(sm5443->dev, "%s: overlap time[0x%x] enable\n", __func__, verify_reg);
				else
					dev_info(sm5443->dev, "%s: overlap time[0x%x]\n", __func__, verify_reg);
				break;
			}
		}
		if (i == 3) {
			dev_err(sm5443->dev, "%s: fail to enable op_mode\n", __func__);
			return -EINVAL;
		}
	}

	return sm5443_update_reg(sm5443, SM5443_REG_CNTL1, op_mode, 0x7, 4);
}

static u8 sm5443_get_op_mode(struct sm5443_charger *sm5443)
{
	u8 reg;

	sm5443_read_reg(sm5443, SM5443_REG_CNTL1, &reg);

	return (reg >> 4) & 0x7;
}

static int sm5443_set_wdt_timer(struct sm5443_charger *sm5443, u8 tmr)
{
	return sm5443_update_reg(sm5443, SM5443_REG_CNTL1, tmr, 0x7, 0);
}

static u8 sm5443_get_wdt_timer(struct sm5443_charger *sm5443)
{
	u8 reg = 0x0;

	sm5443_read_reg(sm5443, SM5443_REG_CNTL1, &reg);

	return reg & 0x7;
}

static int sm5443_kick_wdt(struct sm5443_charger *sm5443)
{
	return sm5443_update_reg(sm5443, SM5443_REG_CNTL4, 0x1, 0x1, 7);
}

static int sm5443_set_adcmode(struct sm5443_charger *sm5443, u8 mode)
{
	return sm5443_update_reg(sm5443, SM5443_REG_ADC_CNTL1, mode, 0x1, 6);
}

static int sm5443_enable_adc(struct sm5443_charger *sm5443, bool enable)
{
	return sm5443_update_reg(sm5443, SM5443_REG_ADC_CNTL1, enable, 0x1, 7);
}

static int sm5443_enable_adc_oneshot(struct sm5443_charger *sm5443, u8 enable)
{
	int ret, cnt;
	u8 reg;

	if (enable) {
		for (cnt = 0; cnt < 3; ++cnt) {
			if (sm5443->pdata->rev_id < 1)
				ret = sm5443_write_reg(sm5443, SM5443_REG_ADC_CNTL1, 0x80);
			else
				ret = sm5443_write_reg(sm5443, SM5443_REG_ADC_CNTL1, 0xC0);
			/* ADC update time */
			msleep(25);
			sm5443_get_flag_irq(sm5443, NULL, NULL, &reg, NULL, NULL, NULL, NULL);
			if ((reg & SM5443_FLAG3_ADCDONE) == 0)
				dev_info(sm5443->dev, "%s: fail to adc done(FLAG3=0x%02X)\n", __func__, reg);
			else
				break;
		}
	} else {
		if (sm5443->pdata->rev_id < 1)
			ret = sm5443_write_reg(sm5443, SM5443_REG_ADC_CNTL1, 0x80);
		else
			ret = sm5443_write_reg(sm5443, SM5443_REG_ADC_CNTL1, 0x0);
	}

	return ret;
}

static int sm5443_get_enadc(struct sm5443_charger *sm5443)
{
	u8 reg = 0x0;

	sm5443_read_reg(sm5443, SM5443_REG_ADC_CNTL1, &reg);

	return (reg >> 7) & 0x1;
}

static int sm5443_sw_reset(struct sm5443_charger *sm5443)
{
	u8 i, reg;

	sm5443_update_reg(sm5443, SM5443_REG_CNTL1, 1, 0x1, 7);     /* Do SW Reset */

	for (i = 0; i < 0xff; ++i) {
		usleep_range(1000, 2000);
		sm5443_read_reg(sm5443, SM5443_REG_CNTL1, &reg);
		if (!((reg >> 7) & 0x1))
			break;
	}

	if (i == 0xff) {
		dev_err(sm5443->dev, "%s: didn't clear reset bit\n", __func__);
		return -EBUSY;
	}
	return 0;
}

static int sm5443_get_charging_config(struct sm5443_charger *sm5443)
{
	switch (sm5443->call_state) {
	case 0:
		sm5443_get_ibuslim(sm5443);
		break;
	case 1:
		sm5443_get_vbatreg(sm5443);
		break;
	case 2:
		sm5443_get_freq(sm5443);
		break;
	}

	sm5443->call_state = (sm5443->call_state + 1) % 3;
	return 0;
}

static u8 sm5443_get_reverse_boost_ocp(struct sm5443_charger *sm5443)
{
	u8 reg, op_mode;
	u8 revbsocp = 0;

	op_mode = sm5443_get_op_mode(sm5443);
	if (op_mode == OP_MODE_INIT) {
		sm5443_get_flag_irq(sm5443, NULL, NULL, NULL, &reg, NULL, NULL, NULL);
		dev_info(sm5443->dev, "%s: FLAG4=0x%x\n", __func__, reg);
		if (reg & SM5443_FLAG4_IBUSOCP_RVS) {
			revbsocp = 1;
			dev_err(sm5443->dev, "%s: detect reverse_boost_ocp\n", __func__);
		}
	}
	return revbsocp;
}

static int sm5443_enable_comp(struct sm5443_charger *sm5443, bool enable)
{
	return sm5443_update_reg(sm5443, SM5443_REG_CNTL2, enable, 0x1, 3);
}

static void sm5443_init_reg_param(struct sm5443_charger *sm5443)
{
	sm5443_set_wdt_timer(sm5443, WDT_TIMER_S_40);
	sm5443_set_freq(sm5443, sm5443->pdata->freq[2]); /* FREQ */
	sm5443_write_reg(sm5443, SM5443_REG_CNTL3, 0xF5); /* VIN2VOUTUVP = off */
	sm5443_write_reg(sm5443, SM5443_REG_INOUT_PROT1, 0x87); /* IBUSUCP = 100mA */
	sm5443_write_reg(sm5443, SM5443_REG_REG1, 0x05); /* VBATOVP = VBATREG + 100mV */
	sm5443_write_reg(sm5443, SM5443_REG_EXT1_CNTL, 0xBC); /* EXT1OVP = 19V */
	sm5443_write_reg(sm5443, SM5443_REG_EXT2_CNTL, 0xBC); /* EXT2OVP = 19V */
	sm5443_write_reg(sm5443, SM5443_REG_CNTL5, 0x0F); /* IBUSOCP_RVS = off, VINOKP = off, IBUSOCP =+ 800mA */
	sm5443_write_reg(sm5443, SM5443_REG_CNTL4, 0x0F); /* VDSQREG_OVP = off */
	sm5443_write_reg(sm5443, SM5443_REG_DG_TIMER_2, 0x60); /* IBUSUCP_DG = 5ms */
	if (sm5443->pdata->rev_id < 1) {
		sm5443_write_reg(sm5443, SM5443_REG_ADC_CNTL1, 0x80); /* ADC = on */
		sm5443_write_reg(sm5443, SM5443_REG_EXTFET_CNTL, 0x10); /* VEXT1DRV = 7.5V */
	} else {
		sm5443_write_reg(sm5443, SM5443_REG_EXTFET_CNTL, 0x68); /* VEXT1DRV = 5V, EXTPROT = 1V */
	}
}

static struct sm_dc_info *select_sm_dc_info(struct sm5443_charger *sm5443)
{
	struct sm_dc_info *p_dc;

	if (sm5443->ps_type == SM_DC_POWER_SUPPLY_PD)
		p_dc = sm5443->pps_dc;
	else
		p_dc = sm5443->wpc_dc;

	return p_dc;
}

static int sm5443_update_vbatreg_by_vnow(struct sm5443_charger *sm5443, int vnow)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	u32 vbatreg;

	vbatreg = sm5443_get_vbatreg(sm5443);
	if ((sm_dc_get_current_state(sm_dc) > SM_DC_UPDAT_BAT) &&
		(vbatreg == SM5443_PRESET_VBATREG))
		return 0;

	/* If 4460mV < VNOW, set VBATREG to 4450mV */
	if (vnow > SM5443_FG_VNOW_MAX) {
		if (sm_dc->wq.cv_vnow_high == 0 && sm_dc_get_current_state(sm_dc) == SM_DC_CV) {
			sm_dc->wq.cv_vnow_high = 1;
			pr_info("%s %s: cv_vnow_high(%dmV)\n", sm_dc->name, __func__, vnow);
		}
		if ((sm_dc_get_current_state(sm_dc) > SM_DC_UPDAT_BAT) &&
			(vbatreg != SM5443_CV_VBATREG)) {
			pr_info("%s %s: update VBATREG [%dmV] to [%dmV]\n", sm_dc->name,
			__func__, vbatreg, SM5443_CV_VBATREG);
			sm5443_set_vbatreg(sm5443, SM5443_CV_VBATREG);
		}
	}
	return 0;
}

static int sm5443_get_vnow(struct sm5443_charger *sm5443)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	union power_supply_propval value = {0, };
	int ret;

	if (sm5443->pdata->en_vbatreg)
		return 0;

	value.intval = SEC_BATTERY_VOLTAGE_MV;
	ret = psy_do_property(sm5443->pdata->battery.fuelgauge_name, get,
			POWER_SUPPLY_PROP_VOLTAGE_NOW, value);
	if (ret < 0) {
		dev_err(sm5443->dev, "%s: cannot get vnow from fg\n", __func__);
		return -EINVAL;
	}
	pr_info("%s %s: vnow=%dmV, target_vbat=%dmV\n", sm_dc->name,
		__func__, value.intval, sm_dc->target_vbat);

	return value.intval;
}

static int sm5443_convert_adc(struct sm5443_charger *sm5443, u8 index)
{
	u8 regs[4] = {0x0, };
	u8 ret = 0x0;
	int adc, cnt;

#if !defined(CONFIG_SEC_FACTORY) && !IS_ENABLED(CONFIG_DUAL_BATTERY)
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);

	if (sm_dc_get_current_state(sm_dc) < SM_DC_CHECK_VBAT
		&& !(sm5443->rev_boost) && (sm_dc->chip_id != SM5443_SUB)) {
		/* Didn't worked ADC block during on CHG-OFF status */
		return 0;
	}
#endif

	for (cnt = 0; cnt < 2; ++cnt) {
		if (sm5443_get_enadc(sm5443) == 0)
			sm5443_enable_adc_oneshot(sm5443, 1);

		switch (index) {
		case SM5443_ADC_THEM:   /* unit - mV */
				sm5443_bulk_read(sm5443, SM5443_REG_NCT_ADC_H, 2, regs);
			adc = (((int)(regs[0] & 0x0F) << 8) + regs[1] + 1) >> 1;
			break;
		case SM5443_ADC_TDIE:   /* unit - C */
			sm5443_read_reg(sm5443, SM5443_REG_TDIE_ADC, regs);
			adc = -40 + regs[0];
			break;
		case SM5443_ADC_VBUS:
			sm5443_bulk_read(sm5443, SM5443_REG_VIN_ADC_H, 2, regs);
			adc = (((int)(regs[0] & 0x0F) << 8) + regs[1]) * 9;
			break;
		case SM5443_ADC_IBUS:
			sm5443_bulk_read(sm5443, SM5443_REG_IBUS_ADC_H, 2, regs);
			adc = (((int)(regs[0] & 0x0F) << 8) + regs[1]) * 25 / 10;
			break;
		case SM5443_ADC_VBAT:
			sm5443_bulk_read(sm5443, SM5443_REG_VBAT_ADC_H, 2, regs);
			adc = (((int)(regs[0] & 0x0F) << 8) + regs[1]) * 125 / 100;
			break;
		case SM5443_ADC_VOUT:
			sm5443_bulk_read(sm5443, SM5443_REG_VOUT_ADC_H, 2, regs);
			adc = (((int)(regs[0] & 0x0F) << 8) + regs[1]) * 125 / 100;
			break;
		case SM5443_ADC_VEXT1:
			sm5443_bulk_read(sm5443, SM5443_REG_VEXT1_ADC_H, 2, regs);
			adc = (((int)(regs[0] & 0x0F) << 8) + regs[1]) * 9;
			break;
		case SM5443_ADC_VEXT2:
			sm5443_bulk_read(sm5443, SM5443_REG_VEXT2_ADC_H, 2, regs);
			adc = (((int)(regs[0] & 0x0F) << 8) + regs[1]) * 9;
			break;
		case SM5443_ADC_PMID:
			sm5443_bulk_read(sm5443, SM5443_REG_PMID_ADC_H, 2, regs);
			adc = (((int)(regs[0] & 0x0F) << 8) + regs[1]) * 9;
			break;
		default:
			adc = 0;
			break;
		}

		/* prevent for reset of register */
		ret = sm5443_get_wdt_timer(sm5443);
		if (ret != WDT_TIMER_S_40) {
			dev_err(sm5443->dev, "%s: detected REG Reset condition(ret=0x%x)\n", __func__, ret);
			sm5443_init_reg_param(sm5443);
		} else {
			break;
		}
	}
	dev_info(sm5443->dev, "%s: index(%d)=[0x%02X,0x%02X], adc=%d\n",
		__func__, index, regs[0], regs[1], adc);

	return adc;
}

static int sm5443_set_adc_mode(struct i2c_client *i2c, u8 mode)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);

	switch (mode) {
	case SM_DC_ADC_MODE_ONESHOT:
		/* covered by continuous mode */
	case SM_DC_ADC_MODE_CONTINUOUS:
		/* SM5443 continuous mode reflash time : 200ms */
		sm5443_set_adcmode(sm5443, 0);
		sm5443_enable_adc(sm5443, 1);
		break;
	case SM_DC_ADC_MODE_OFF:
	default:
		sm5443_set_adcmode(sm5443, 0);
		if (sm5443->pdata->rev_id < 1)
			sm5443_enable_adc(sm5443, 1);
		else
			sm5443_enable_adc(sm5443, 0);
		break;
	}

	return 0;
}

static void sm5443_set_ext_ctrl(struct sm5443_charger *sm5443, u8 mode)
{
	if (sm5443->pdata->rev_id < 1) {
		switch (mode) {
		case SM5443_EXTMODE_WIRED_CHG /* wired chg */:
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 1, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 0, 0x1, 6);
			break;
		case SM5443_EXTMODE_WIRELESS_CHG /* wireless chg */:
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 0, 0x1, 6);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 1, 0x1, 6);
			break;
		case SM5443_EXTMODE_WIRED_SHR /* wired sharing */:
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 1, 0x1, 6);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 0, 0x1, 6);
			break;
		case SM5443_EXTMODE_WIRELESS_SHR /* wireless sharing */:
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 1, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 1, 0x1, 6);
			break;
		default:
			break;
		}
	} else {
		switch (mode) {
		case SM5443_EXTMODE_WIRED_CHG /* wired chg */:
		case SM5443_EXTMODE_WIRED_SHR /* wired sharing */:
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 1, 0x1, 6);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 0, 0x1, 6);
			break;
		case SM5443_EXTMODE_WIRELESS_CHG /* wireless chg */:
		case SM5443_EXTMODE_WIRELESS_SHR /* wireless sharing */:
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT1_CNTL, 0, 0x1, 6);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 0, 0x1, 7);
			sm5443_update_reg(sm5443, SM5443_REG_EXT2_CNTL, 1, 0x1, 6);
			break;
		default:
			break;
		}
	}
	dev_info(sm5443->dev, "%s: mode=%d\n", __func__, mode);
}

static void sm5443_print_regmap(struct sm5443_charger *sm5443)
{
	u8 print_reg_num, regs[64] = {0x0,};
	char temp_buf[256] = {0,};
	char reg_addr[8] = {0x11, 0x1B,};
	u8 reg_data;
	int i;

	print_reg_num = SM5443_REG_REG1 - SM5443_REG_DEVICE_ID + 1;
	sm5443_bulk_read(sm5443, SM5443_REG_DEVICE_ID, print_reg_num, regs);
	for (i = 0; i < print_reg_num; ++i)
		sprintf(temp_buf+strlen(temp_buf), "0x%02X[0x%02X],", SM5443_REG_DEVICE_ID + i, regs[i]);

	pr_info("sm5443-charger: regmap: %s\n", temp_buf);
	memset(temp_buf, 0x0, sizeof(temp_buf));

	print_reg_num = 2;
	for (i = 0; i < print_reg_num; ++i) {
		sm5443_read_reg(sm5443, reg_addr[i], &reg_data);
		sprintf(temp_buf+strlen(temp_buf), "0x%02X[0x%02X],", reg_addr[i], reg_data);
	}

	print_reg_num = SM5443_REG_DG_TIMER_3 - SM5443_REG_EXT1_CNTL + 1;
	sm5443_bulk_read(sm5443, SM5443_REG_EXT1_CNTL, print_reg_num, regs);
	for (i = 0; i < print_reg_num; ++i)
		sprintf(temp_buf+strlen(temp_buf), "0x%02X[0x%02X],", SM5443_REG_EXT1_CNTL + i, regs[i]);

	sm5443_read_reg(sm5443, SM5443_REG_CNTL5, &reg_data);
	sprintf(temp_buf+strlen(temp_buf), "0x%02X[0x%02X],", SM5443_REG_CNTL5, reg_data);

	/* Driver ver */
	sprintf(temp_buf+strlen(temp_buf), "Ver[%s]", SM5443_DC_VERSION);

	pr_info("sm5443-charger: regmap: %s\n", temp_buf);
	memset(temp_buf, 0x0, sizeof(temp_buf));
}

static int sm5443_reverse_boost_enable(struct sm5443_charger *sm5443, int op_mode)
{
	u8 i, flag3, flag4;

	if (op_mode && !sm5443->rev_boost) {
		if (op_mode == OP_MODE_REV_BOOST) {
			dev_err(sm5443->dev, "%s: 1to2 is not available in the current version\n", __func__);
			return -EINVAL;
		}

		for (i = 0; i < 2; ++i) {
			sm5443_get_flag_status(sm5443, NULL, NULL, &flag3, NULL, NULL, NULL, NULL);
			dev_info(sm5443->dev, "%s: FLAG3:0x%x i=%d\n", __func__, flag3, i);
			if (flag3 & (SM5443_FLAG3_VINUVLO | SM5443_FLAG3_VINPOK))
				msleep(20);
			else
				break;
		}

		sm5443_set_op_mode(sm5443, op_mode);
		for (i = 0; i < 12; ++i) {
			usleep_range(10000, 11000);
			sm5443_get_flag_status(sm5443, NULL, NULL, NULL, &flag4, NULL, NULL, NULL);
			dev_info(sm5443->dev, "%s: i=%d\n", __func__, i);
			if (flag4 & SM5443_FLAG4_RVSRDY) {
				sm5443_set_ext_ctrl(sm5443, SM5443_EXTMODE_WIRED_SHR);
				break;
			}
		}
		if (i == 12) {
			dev_err(sm5443->dev, "%s: fail to reverse boost enable\n", __func__);
			sm5443_set_op_mode(sm5443, OP_MODE_INIT);
			sm5443->rev_boost = false;
			return -EINVAL;
		}
		sm5443_set_adc_mode(sm5443->i2c, SM_DC_ADC_MODE_CONTINUOUS);
		dev_info(sm5443->dev, "%s: ON\n", __func__);
	} else if (!op_mode) {
		sm5443_set_op_mode(sm5443, OP_MODE_INIT);
		sm5443_set_adc_mode(sm5443->i2c, SM_DC_ADC_MODE_OFF);
		dev_info(sm5443->dev, "%s: OFF\n", __func__);
	}
	sm5443->rev_boost = op_mode < 1 ? 0 : 1;

	return 0;
}

static bool sm5443_check_charging_enable(struct sm5443_charger *sm5443)
{
	u8 reg;

	reg = sm5443_get_op_mode(sm5443);
	if (reg == OP_MODE_FW_BOOST || reg == OP_MODE_FW_3TO1 || reg == OP_MODE_FW_BYPASS)
		return true;
	else
		return false;
}

static int sm5443_start_charging(struct sm5443_charger *sm5443)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int state = sm_dc_get_current_state(sm_dc);
	struct power_supply *psy_dc_sub = NULL;
	struct sm5443_charger *sm5443_sub = NULL;
	int ret;

	if (sm5443->cable_online < 1) {
		dev_err(sm5443->dev, "%s: can't detect valid cable connection(online=%d)\n",
			__func__, sm5443->cable_online);
		return -ENODEV;
	}

	/* Check dc mode */
	if (sm_dc->chip_id != SM5443_SUB) {
		psy_dc_sub = power_supply_get_by_name("sm5443-charger-sub");
		if (!psy_dc_sub) {
			sm_dc->i2c_sub = NULL;
			dev_info(sm5443->dev, "%s: start single dc mode\n", __func__);
		} else {
			if (sm5443->ta_type == SM5443_TA_WIRELESS) {
				sm_dc->i2c_sub = NULL;
				dev_info(sm5443->dev, "%s: In wireless, start single DC mode\n", __func__);
			} else {
				sm5443_sub = power_supply_get_drvdata(psy_dc_sub);
				sm_dc->i2c_sub = sm5443_sub->i2c;
				dev_info(sm5443->dev, "%s: start dual dc mode\n", __func__);
			}
		}
	} else {
		dev_info(sm5443->dev, "%s: unable to start sub dc standalone\n", __func__);
		return -EINVAL;
	}

	if (state < SM_DC_CHECK_VBAT) {
		dev_info(sm5443->dev, "%s: charging off state (state=%d)\n", __func__, state);
		ret = sm5443_sw_reset(sm5443);
		if (ret < 0) {
			dev_err(sm5443->dev, "%s: fail to sw reset(ret=%d)\n", __func__, ret);
			return ret;
		}
		sm5443_init_reg_param(sm5443);
		sm5443_enable_comp(sm5443, 1);

		if (sm5443->ta_type == SM5443_TA_WIRELESS)
			sm5443_set_ext_ctrl(sm5443, SM5443_EXTMODE_WIRELESS_CHG);
		else
			sm5443_set_ext_ctrl(sm5443, SM5443_EXTMODE_WIRED_CHG);

		if (sm5443_sub) {
			ret = sm5443_sw_reset(sm5443_sub);
			if (ret < 0) {
				dev_err(sm5443_sub->dev, "%s: fail to sw reset(ret=%d)\n", __func__, ret);
				return ret;
			}
			sm5443_init_reg_param(sm5443_sub);
			sm5443_set_ext_ctrl(sm5443, SM5443_EXTMODE_WIRED_CHG);
		}
	} else if (state >= SM_DC_CV_MAN) {
		dev_info(sm5443->dev, "%s: skip start charging (state=%d)\n", __func__, state);
		return 0;
	}

	if (sm5443->ta_type == SM5443_TA_USBPD_2P0)
		ret = sm_dc_start_fpdo_charging(sm_dc);
	else
		ret = sm_dc_start_charging(sm_dc);

	if (ret < 0) {
		dev_err(sm5443->dev, "%s: fail to start direct-charging\n", __func__);
		return ret;
	}
	__pm_stay_awake(sm5443->chg_ws);

	return 0;
}

static int sm5443_stop_charging(struct sm5443_charger *sm5443)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);

	sm_dc_stop_charging(sm_dc);
	sm5443_enable_comp(sm5443, 0);

	__pm_relax(sm5443->chg_ws);

	return 0;
}

static int sm5443_start_pass_through_charging(struct sm5443_charger *sm5443)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int state = sm_dc_get_current_state(sm_dc);
	int ret;

	if (sm5443->cable_online < 1) {
		dev_err(sm5443->dev, "%s: can't detect valid cable connection(online=%d)\n",
			__func__, sm5443->cable_online);
		return -ENODEV;
	}

	if (state < SM_DC_PRESET) {
		pr_err("%s %s: charging off state (state=%d)\n", sm_dc->name, __func__, sm_dc->state);
		return -ENODEV;
	}

	sm5443_stop_charging(sm5443);
	msleep(200);

	/* Disable IBUSUCP & Set freq*/
	sm5443_set_freq(sm5443, sm5443->pdata->freq[0]); /* FREQ */
	sm5443_write_reg(sm5443, SM5443_REG_CNTL3, 0xF3); /* VIN2VOUTVOVP & VIN2VOUTUVP = disabled */
	sm5443_update_reg(sm5443, SM5443_REG_INOUT_PROT1, 0, 0x1, 7); /* IBUSUCP = disabled */

	ret = sm_dc_start_manual_charging(sm_dc);
	if (ret < 0) {
		dev_err(sm5443->dev, "%s: fail to start direct-charging\n", __func__);
		return ret;
	}
	__pm_stay_awake(sm5443->chg_ws);

	return 0;
}

static int sm5443_set_pass_through_ta_vol(struct sm5443_charger *sm5443, int delta_soc)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int state = sm_dc_get_current_state(sm_dc);

	if (sm5443->cable_online < 1) {
		dev_err(sm5443->dev, "%s: can't detect valid cable connection(online=%d)\n",
			__func__, sm5443->cable_online);
		return -ENODEV;
	}

	if (state != SM_DC_CV_MAN) {
		pr_err("%s %s: pass-through mode was not set.(dc state = %d)\n", sm_dc->name, __func__, sm_dc->state);
		return -ENODEV;
	}

	return sm_dc_set_ta_volt_by_soc(sm_dc, delta_soc);
}

static int sm5443_get_err_node(struct sm5443_charger *sm5443)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);

	dev_info(sm5443->dev, "%s: err_node=0x%06X, dc_err_idx=0x%08X, retry_cnt:%d\n",
		__func__, sm_dc->err_node, sm_dc->wq.dc_err_idx, sm_dc->wq.retry_cnt);

	return sm_dc->err_node;
}

static int sm5443_set_err_node(struct sm5443_charger *sm5443, u32 err_idx)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);

	int err_node = SM_DC_ERR_NODE_NONE;

	if (err_idx & SM_DC_ERR_VINUVLO)
		err_node = SM_DC_ERR_NODE_VIN_UVLO;
	else if (err_idx & SM_DC_ERR_VINOVP)
		err_node = SM_DC_ERR_NODE_VIN_OVP;
	else if (err_idx & SM_DC_ERR_VBATOVP)
		err_node = SM_DC_ERR_NODE_VBAT_OVP;
	else if (err_idx & SM_DC_ERR_IBUSOCP)
		err_node = SM_DC_ERR_NODE_IBUS_OCP;
	else if (err_idx & SM_DC_ERR_IBUSUCP)
		err_node = SM_DC_ERR_NODE_IBUS_UCP;
	else if (err_idx & SM_DC_ERR_IBATOCP)
		err_node = SM_DC_ERR_NODE_IBAT_OCP;
	else if (err_idx & SM_DC_ERR_CFLY_SHORT)
		err_node = SM_DC_ERR_NODE_CFLY_SHORT;
	else if (err_idx & SM_DC_ERR_CN_SHORT)
		err_node = SM_DC_ERR_NODE_CN_SHORT;
	else if (err_idx & SM_DC_ERR_TSD)
		err_node = SM_DC_ERR_NODE_THERMAL_SHUTDOWN;
	else if (err_idx & SM_DC_ERR_WTDTMR)
		err_node = SM_DC_ERR_NODE_WATCHDOG_TIMER;
	else if (err_idx & SM_DC_ERR_VIN2OUTUVP)
		err_node = SM_DC_ERR_NODE_VBUS2VOUT_RELATIVE_UVP;
	else if (err_idx & SM_DC_ERR_VIN2OUTOVP)
		err_node = SM_DC_ERR_NODE_VBUS2VOUT_RELATIVE_OVP;
	else if (err_idx & SM_DC_ERR_VDSQREG)
		err_node = SM_DC_ERR_NODE_VDSQRB_OVP;

	sm_dc->err_node = err_node;
	dev_info(sm5443->dev, "%s: err_node=0x%06X, err_idx=0x%08X, retry_cnt:%d\n",
		__func__, sm_dc->err_node, err_idx, sm_dc->wq.retry_cnt);

	return 1;
}

static u32 sm5443_get_dc_flag_status(struct i2c_client *i2c)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int state = sm_dc_get_current_state(sm_dc);
	u8 flag1, flag2, flag3, flag4, flag5, flag6, flag7, op_mode;
	u8 flag1_s, flag2_s, flag3_s, flag4_s, flag5_s, flag6_s, flag7_s;
	u32 err = SM_DC_ERR_NONE;
	int i, vnow = 0;

	mutex_lock(&sm5443->i2c_lock);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG1, &flag1);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG2, &flag2);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG3, &flag3);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG4, &flag4);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG5, &flag5);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG6, &flag6);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG7, &flag7);
	pr_info("%s %s: FLAG:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x\n", sm_dc->name,
		__func__, flag1, flag2, flag3, flag4, flag5, flag6, flag7);

	sm5443_read_reg(sm5443, SM5443_REG_FLAG1, &flag1_s);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG2, &flag2_s);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG3, &flag3_s);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG4, &flag4_s);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG5, &flag5_s);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG6, &flag6_s);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG7, &flag7_s);
	op_mode = sm5443_get_op_mode(sm5443);
	pr_info("%s %s: FLAG:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x op_mode=0x%x\n", sm_dc->name,
		__func__, flag1_s, flag2_s, flag3_s, flag4_s, flag5_s, flag6_s, flag7_s, op_mode);
	mutex_unlock(&sm5443->i2c_lock);

	sm5443_get_charging_config(sm5443);

	if (sm_dc->chip_id != SM5443_SUB)
		vnow = sm5443_get_vnow(sm5443);

	if (op_mode == OP_MODE_INIT) {
		if ((flag1 & SM5443_FLAG1_IBUSUCP) || (flag1_s & SM5443_FLAG1_IBUSUCP)) {
			err += SM_DC_ERR_IBUSUCP;
			sm_dc_report_ibusucp(sm_dc);
		}
		if ((flag3 & SM5443_FLAG3_VINUVLO) || (flag3_s & SM5443_FLAG3_VINUVLO))
			err += SM_DC_ERR_VINUVLO;
		if ((flag1 & SM5443_FLAG1_VINOVP) || (flag1_s & SM5443_FLAG1_VINOVP))
			err += SM_DC_ERR_VINOVP;
		if ((flag1 & SM5443_FLAG1_IBUSOCP) || (flag1_s & SM5443_FLAG1_IBUSOCP))
			err += SM_DC_ERR_IBUSOCP;
		if ((flag1 & SM5443_FLAG1_PMID2VOUT_UVP) || (flag1_s & SM5443_FLAG1_PMID2VOUT_UVP))
			err += SM_DC_ERR_PMID2VOUT_UVP;
		if ((flag1 & SM5443_FLAG1_PMID2VOUT_OVP) || (flag1_s & SM5443_FLAG1_PMID2VOUT_OVP))
			err += SM_DC_ERR_PMID2VOUT_OVP;
		if ((flag1 & SM5443_FLAG1_VDSQREGP) || (flag1_s & SM5443_FLAG1_VDSQREGP))
			err += SM_DC_ERR_VDSQREG;
		if ((flag2 & SM5443_FLAG2_CNSHTP) || (flag2_s & SM5443_FLAG2_CNSHTP))
			err += SM_DC_ERR_CN_SHORT;
		if ((flag2 & SM5443_FLAG2_VIN2OUTOVP) || (flag2_s & SM5443_FLAG2_VIN2OUTOVP))
			err += SM_DC_ERR_VIN2OUTOVP;
		if ((flag2 & SM5443_FLAG2_VIN2OUTUVP) || (flag2_s & SM5443_FLAG2_VIN2OUTUVP))
			err += SM_DC_ERR_VIN2OUTUVP;
		if ((flag2 & SM5443_FLAG2_TSD) || (flag2_s & SM5443_FLAG2_TSD))
			err += SM_DC_ERR_TSD;
		if ((flag2 & SM5443_FLAG2_VBATOVP) || (flag2_s & SM5443_FLAG2_VBATOVP))
			err += SM_DC_ERR_VBATOVP;
		if ((flag4 & SM5443_FLAG4_VOUTOVP) || (flag4_s & SM5443_FLAG4_VOUTOVP))
			err += SM_DC_ERR_VOUTOVP;
		if ((flag4 & SM5443_FLAG4_VOUTUVLO) || (flag4_s & SM5443_FLAG4_VOUTUVLO))
			err += SM_DC_ERR_VOUTUVLO;
		if ((flag5 & SM5443_FLAG5_VEXT1UVLO) || (flag5 & SM5443_FLAG5_VEXT2UVLO))
			err += SM_DC_ERR_VEXT_UVLO;
		if ((flag5 & SM5443_FLAG5_VEXT1OVP) || (flag5 & SM5443_FLAG5_VEXT2OVP))
			err += SM_DC_ERR_VEXT_OVP;

		if (sm_dc->chip_id != SM5443_SUB) {
			if (err & SM_DC_ERR_IBUSOCP) /* IBUSOCP_DG to 2ms for next DC start */
				sm5443->ibusocp = 1;

			sm_dc->wq.dc_err_idx = err;
			if (state == SM_DC_PRE_CC ||
				(state > SM_DC_PRE_CC && sm_dc->wq.retry_cnt == 0))
				sm5443_set_err_node(sm5443, err);

			if ((sm_dc->wq.retry_cnt < 3) && (err & SM_DC_ERR_IBUSUCP)) {
				pr_info("%s %s: try to retry, cnt:%d, err:0x%08X, state=%d\n", sm_dc->name,
						__func__, sm_dc->wq.retry_cnt, err, state);

				sm_dc->wq.retry_cnt++;
				err |= SM_DC_ERR_RETRY;
				return err;
			}
		}

		if (err == SM_DC_ERR_NONE)
			err += SM_DC_ERR_UNKNOWN;

		if (err == SM_DC_ERR_UNKNOWN && sm_dc->chip_id == SM5443_SUB)
			pr_info("%s %s: SM_DC_ERR_NONE\n", sm_dc->name, __func__);
		else
			pr_info("%s %s: SM_DC_ERR(err=0x%x)\n", sm_dc->name, __func__, err);
	} else {
		if (flag3_s & SM5443_FLAG3_VINUVLO) {
			pr_info("%s %s: vbus uvlo detected, try to retry\n", sm_dc->name, __func__);
			err = SM_DC_ERR_RETRY;
		} else if ((flag2 & SM5443_FLAG2_VBATREG) && (flag2_s & SM5443_FLAG2_VBATREG) &&
			(flag4 & SM5443_FLAG4_IBUSREG) && (flag4_s & SM5443_FLAG4_IBUSREG)) {
			for (i = 0; i < 5; ++i) {
				sm5443_get_flag_irq(sm5443, NULL, &flag2, NULL, &flag4, NULL, NULL, NULL);
				sm5443_get_flag_irq(sm5443, NULL, &flag2_s, NULL, &flag4_s, NULL, NULL, NULL);

				if ((flag2 & SM5443_FLAG2_VBATREG) && (flag2_s & SM5443_FLAG2_VBATREG) &&
					(!(flag4 & SM5443_FLAG4_IBUSREG)) && (!(flag4_s & SM5443_FLAG4_IBUSREG))) {
					pr_info("%s %s: VBATREG detected\n", sm_dc->name, __func__);
					err = SM_DC_ERR_VBATREG;
					break;
				}  else if ((flag2 & SM5443_FLAG2_VBATREG) && (flag2_s & SM5443_FLAG2_VBATREG) &&
					(!(flag4 & SM5443_FLAG4_IBUSREG) || !(flag4_s & SM5443_FLAG4_IBUSREG))) {
					if (sm_dc->target_vbat - SM5443_VBATREG_OFFS <= vnow) {
						pr_info("%s %s: VBATREG detected\n", sm_dc->name, __func__);
						err = SM_DC_ERR_VBATREG;
					}
					break;
				}  else if ((flag2 & SM5443_FLAG2_VBATREG) && (flag2_s & SM5443_FLAG2_VBATREG) &&
					(flag4 & SM5443_FLAG4_IBUSREG) && (flag4_s & SM5443_FLAG4_IBUSREG)) {
					if ((i == 4) && (sm_dc->target_vbat - SM5443_VBATREG_OFFS <= vnow)) {
						pr_info("%s %s: VBATREG detected\n", sm_dc->name, __func__);
						err = SM_DC_ERR_VBATREG;
						break;
					}
					continue;
				} else if ((!(flag2 & SM5443_FLAG2_VBATREG)) && (!(flag2_s & SM5443_FLAG2_VBATREG)) &&
					(flag4 & SM5443_FLAG4_IBUSREG) && (flag4_s & SM5443_FLAG4_IBUSREG)) {
					pr_info("%s %s: IBUSREG detected\n", sm_dc->name, __func__);
					err = SM_DC_ERR_IBUSREG;
					break;
				}
				break;
			}
		} else if (((flag2 & SM5443_FLAG2_VBATREG) && (flag2_s & SM5443_FLAG2_VBATREG) &&
			(!(flag4 & SM5443_FLAG4_IBUSREG)) && (!(flag4_s & SM5443_FLAG4_IBUSREG))) ||
			(sm_dc->target_vbat <= vnow)) {
			pr_info("%s %s: VBATREG detected\n", sm_dc->name, __func__);
			err = SM_DC_ERR_VBATREG;
		} else if ((flag4 & SM5443_FLAG4_IBUSREG) && (flag4_s & SM5443_FLAG4_IBUSREG)) {
			pr_info("%s %s: IBUSREG detected\n", sm_dc->name, __func__);
			err = SM_DC_ERR_IBUSREG;
		} else if (vnow < 0) {
			err = SM_DC_ERR_INVAL_VBAT;
			pr_info("%s %s: SM_DC_ERR(err=0x%x)\n", sm_dc->name, __func__, err);
		}

		/* Update VBATREG by VNOW */
		if (err == SM_DC_ERR_VBATREG)
			sm5443_update_vbatreg_by_vnow(sm5443, vnow);
	}

	if (!sm5443->wdt_disable)
		sm5443_kick_wdt(sm5443);

	return err;
}

static int psy_chg_get_online(struct sm5443_charger *sm5443)
{
	u8 flag, vin_pok, cable_online;

	cable_online = sm5443->cable_online < 1 ? 0 : 1;
	sm5443_get_flag_status(sm5443, NULL, NULL, &flag, NULL, NULL, NULL, NULL);
	dev_info(sm5443->dev, "%s: FLAG3=0x%x\n", __func__, flag);
	vin_pok = (flag >> 7) & 0x1;

	if (vin_pok != cable_online) {
		dev_err(sm5443->dev, "%s: mismatched vbus state(vin_pok:%d cable_online:%d)\n",
		__func__, vin_pok, sm5443->cable_online);
	}

	return sm5443->cable_online;
}

static int psy_chg_get_status(struct sm5443_charger *sm5443)
{
	int status = POWER_SUPPLY_STATUS_UNKNOWN;
	u8 flag3;

	sm5443_get_flag_status(sm5443, NULL, NULL, &flag3, NULL, NULL, NULL, NULL);

	if (sm5443_check_charging_enable(sm5443)) {
		status = POWER_SUPPLY_STATUS_CHARGING;
	} else {
		if (flag3 & SM5443_FLAG3_VINPOK) { /* check vin-pok */
			status = POWER_SUPPLY_STATUS_NOT_CHARGING;
		} else {
			status = POWER_SUPPLY_STATUS_DISCHARGING;
		}
	}

	return status;
}

static int psy_chg_get_health(struct sm5443_charger *sm5443)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int state = sm_dc_get_current_state(sm_dc);
	int health = POWER_SUPPLY_HEALTH_GOOD;
	u8 chg_on, flag1;

	if (state == SM_DC_ERR) {
		health = POWER_SUPPLY_EXT_HEALTH_DC_ERR;
		dev_info(sm5443->dev, "%s: chg_state=%d, health=%d\n",
			__func__, state, health);
	} else if (state >= SM_DC_PRE_CC && state <= SM_DC_CV_FPDO) {
		chg_on = sm5443_check_charging_enable(sm5443);
		if (chg_on == false) {
			sm5443_get_flag_irq(sm5443, &flag1, NULL, NULL, NULL, NULL, NULL, NULL);
			if (flag1 & SM5443_FLAG1_IBUSUCP)
				sm_dc_report_ibusucp(sm_dc);

			health = POWER_SUPPLY_EXT_HEALTH_DC_ERR;
		}
		dev_info(sm5443->dev, "%s: chg_on=%d, health=%d\n", __func__, chg_on, health);
	}

	return health;
}

static int psy_chg_get_chg_vol(struct sm5443_charger *sm5443)
{
	u32 chg_vol = sm5443_get_vbatreg(sm5443);

	dev_info(sm5443->dev, "%s: VBAT_REG=%dmV\n", __func__, chg_vol);

	return chg_vol;
}

static int psy_chg_get_input_curr(struct sm5443_charger *sm5443)
{
	u32 input_curr = sm5443_get_ibuslim(sm5443);

	dev_info(sm5443->dev, "%s: IBUSLIM=%dmA\n", __func__, input_curr);

	return input_curr;
}

static int psy_chg_get_opmode_ratio(struct sm5443_charger *sm5443)
{
	u8 op_mode = sm5443_get_op_mode(sm5443);
	u8 ret;

	if (op_mode == OP_MODE_FW_BOOST)
		ret = DC_MODE_2TO1;
	else if (op_mode == OP_MODE_FW_3TO1)
		ret = DC_MODE_3TO1;
	else
		ret = op_mode;

	dev_info(sm5443->dev, "%s: DC_MODE=%d\n", __func__, ret);

	return op_mode;
}

static int psy_chg_get_ext_monitor_work(struct sm5443_charger *sm5443)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int state = sm_dc_get_current_state(sm_dc);
	int adc_vbus, adc_ibus, adc_vbat, adc_them, adc_tdie, adc_vext1, adc_vext2;

	if (state < SM_DC_CHECK_VBAT && (sm_dc->chip_id != SM5443_SUB)) {
		dev_info(sm5443->dev, "%s: charging off state (state=%d)\n", __func__, state);
		return -EINVAL;
	}

	adc_vbus = sm5443_convert_adc(sm5443, SM5443_ADC_VBUS);
	adc_ibus = sm5443_convert_adc(sm5443, SM5443_ADC_IBUS);
	adc_vbat = sm5443_convert_adc(sm5443, SM5443_ADC_VBAT);
	adc_them = sm5443_convert_adc(sm5443, SM5443_ADC_THEM);
	adc_tdie = sm5443_convert_adc(sm5443, SM5443_ADC_TDIE);
	adc_vext1 = sm5443_convert_adc(sm5443, SM5443_ADC_VEXT1);
	adc_vext2 = sm5443_convert_adc(sm5443, SM5443_ADC_VEXT2);

	pr_info("sm5443-charger: adc_monitor: vbus:%d:ibus:%d:vbat:%d:them:%d:tdie:%d:ext1:%d:ext2:%d\n",
		adc_vbus, adc_ibus, adc_vbat, adc_them, adc_tdie, adc_vext1, adc_vext2);
	sm5443_print_regmap(sm5443);

	return 0;
}

static int psy_chg_get_ext_measure_input(struct sm5443_charger *sm5443, int index)
{
	struct sm5443_charger *sm5443_sub = NULL;
	struct power_supply *psy_dc_sub = NULL;
	int adc = 0;

	if (sm5443->chip_id != SM5443_SUB) {
		psy_dc_sub = power_supply_get_by_name("sm5443-charger-sub");
		if (!psy_dc_sub)
			sm5443_sub = NULL;
		else
			sm5443_sub = power_supply_get_drvdata(psy_dc_sub);
	}

	switch (index) {
	case SEC_BATTERY_IIN_MA:
		if (sm5443_sub)
			adc = sm5443_convert_adc(sm5443_sub, SM5443_ADC_IBUS);
		adc += sm5443_convert_adc(sm5443, SM5443_ADC_IBUS);
		break;
	case SEC_BATTERY_IIN_UA:
		if (sm5443_sub)
			adc = sm5443_convert_adc(sm5443_sub, SM5443_ADC_IBUS) * 1000;
		adc += sm5443_convert_adc(sm5443, SM5443_ADC_IBUS) * 1000;
		break;
	case SEC_BATTERY_VIN_MA:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_VBUS);
		break;
	case SEC_BATTERY_VIN_UA:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_VBUS) * 1000;
		break;
	default:
		adc = 0;
		break;
	}

	dev_info(sm5443->dev, "%s: index=%d, adc=%d\n", __func__, index, adc);

	return adc;
}

static int psy_chg_get_ext_d2d_reverse_voltage(struct sm5443_charger *sm5443)
{
	int ret = 0;

	if (sm5443->rev_boost) {
		ret = sm5443_get_op_mode(sm5443);
		if (ret >= OP_MODE_REV_BYPASS) {
			ret = 1;
		} else {
			ret = -EINVAL;
			dev_err(sm5443->dev, "%s: REVESE OP_MODE err\n", __func__);
		}
	}
	dev_info(sm5443->dev, "%s: ret=%d\n", __func__, ret);

	return ret;
}

static const char * const sm5443_dc_state_str[] = {
	"NO_CHARGING", "DC_ERR", "CHARGING_DONE", "CHECK_VBAT", "PRESET_DC",
	"ADJUST_CC", "UPDATE_BAT", "CC_MODE", "CV_MODE", "CV_MAN_MODE", "CV_FPDO_MODE"
};
static int psy_chg_get_ext_direct_charger_chg_status(
		struct sm5443_charger *sm5443, union power_supply_propval *val)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int state = sm_dc_get_current_state(sm_dc);

	val->strval = sm5443_dc_state_str[state];
	pr_info("%s: CHARGER_STATUS(%s)\n", __func__, val->strval);

	return 0;
}

static int sm5443_chg_get_property(struct power_supply *psy,
	enum power_supply_property psp, union power_supply_propval *val)
{
	struct sm5443_charger *sm5443 = power_supply_get_drvdata(psy);
	enum power_supply_ext_property ext_psp =
		(enum power_supply_ext_property)psp;
	int adc_them;

	dev_info(sm5443->dev, "%s: psp=%d\n", __func__, psp);

	if (atomic_read(&sm5443->shutdown_cnt) > 0) {
		dev_info(sm5443->dev, "%s: DC already shutdown\n", __func__);
		return -EINVAL;
	}

	switch ((int)psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = psy_chg_get_online(sm5443);
		break;
	case POWER_SUPPLY_PROP_STATUS:
		val->intval = psy_chg_get_status(sm5443);
		break;
	case POWER_SUPPLY_PROP_HEALTH:
		val->intval = psy_chg_get_health(sm5443);
		break;
	case POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE:
		val->intval = psy_chg_get_chg_vol(sm5443);
		break;
	case POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT:
		val->intval = psy_chg_get_input_curr(sm5443);
		break;
	case POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT:
		val->intval = sm5443->target_ibat;
		break;
	case POWER_SUPPLY_PROP_TEMP:
		adc_them = sm5443_convert_adc(sm5443, SM5443_ADC_THEM);
		val->intval = adc_them;
		break;
#if IS_ENABLED(CONFIG_DUAL_BATTERY)
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		val->intval = sm5443_convert_adc(sm5443, SM5443_ADC_VBAT);
		break;
#endif
	case POWER_SUPPLY_EXT_PROP_MIN ... POWER_SUPPLY_EXT_PROP_MAX:
		switch (ext_psp) {
		case POWER_SUPPLY_EXT_PROP_CHARGING_ENABLED:
			val->intval = sm5443_check_charging_enable(sm5443);
			break;
		case POWER_SUPPLY_EXT_PROP_DC_OP_MODE:
			val->intval = psy_chg_get_opmode_ratio(sm5443);
			break;
		case POWER_SUPPLY_EXT_PROP_MONITOR_WORK:
			psy_chg_get_ext_monitor_work(sm5443);
			break;
		case POWER_SUPPLY_EXT_PROP_MEASURE_INPUT:
			val->intval = psy_chg_get_ext_measure_input(sm5443, val->intval);
			break;
		case POWER_SUPPLY_EXT_PROP_MEASURE_SYS:
			dev_err(sm5443->dev, "%s: need to works\n", __func__);
			/*
			 *  Need to check operation details.. by SEC.
			 */
			val->intval = -EINVAL;
			break;
		case POWER_SUPPLY_EXT_PROP_DIRECT_CHARGER_CHG_STATUS:
			psy_chg_get_ext_direct_charger_chg_status(sm5443, val);
			break;

		case POWER_SUPPLY_EXT_PROP_PASS_THROUGH_MODE:
			break;

		case POWER_SUPPLY_EXT_PROP_PASS_THROUGH_MODE_TA_VOL:
			break;

		case POWER_SUPPLY_EXT_PROP_D2D_REVERSE_VOLTAGE:
			val->intval = psy_chg_get_ext_d2d_reverse_voltage(sm5443);
			break;

		case POWER_SUPPLY_EXT_PROP_D2D_REVERSE_OCP:
			val->intval = sm5443_get_reverse_boost_ocp(sm5443);
			break;

		case POWER_SUPPLY_EXT_PROP_DC_ERROR_CAUSE:
			/* Get dc err cause */
			val->intval = sm5443_get_err_node(sm5443);
			break;

		default:
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int psy_chg_set_online(struct sm5443_charger *sm5443, int online)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int ret = 0;
	union power_supply_propval val = {0, };

	dev_info(sm5443->dev, "%s: online=%d\n", __func__, online);

	if (online < 2) {
		if (sm_dc_get_current_state(sm_dc) > SM_DC_EOC)
			sm5443_stop_charging(sm5443);
	}
	sm5443->cable_online = online;

	if (online > 0) {
		/* Get TA type information from battery psy */
		psy_do_property("battery", get, POWER_SUPPLY_PROP_ONLINE, val);
		dev_info(sm5443->dev, "%s: ta_type=%d\n", __func__, val.intval);

		if (val.intval == SEC_BATTERY_CABLE_FPDO_DC) {
			/* The TA type is USBPD charger with only fixed PDO */
			sm5443->ta_type = SM5443_TA_USBPD_2P0;
			sm5443->ps_type = SM_DC_POWER_SUPPLY_PD;
#if IS_ENABLED(CONFIG_BATTERY_SAMSUNG)
		} else if (is_3_1_wc_status(sm5443->cable_online)) {
			sm5443->ta_type = SM5443_TA_WIRELESS;
			sm5443->ps_type = SM_DC_POWER_SUPPLY_WPC;
#endif
		} else {
			sm5443->ta_type = SM5443_TA_USBPD;
			sm5443->ps_type = SM_DC_POWER_SUPPLY_PD;
		}
		dev_info(sm5443->dev, "%s: sm5443->ta_type=%d\n", __func__, sm5443->ta_type);
	}
	return ret;
}

static int psy_chg_set_const_chg_voltage(struct sm5443_charger *sm5443, int vbat)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	struct sm_dc_info *wpc_dc = sm5443->wpc_dc;
	int state = sm_dc_get_current_state(sm_dc);
	int ret = 0;

	dev_info(sm5443->dev, "%s: [%dmV] to [%dmV]\n", __func__, sm5443->target_vbat, vbat);

	if (state == SM_DC_CV_FPDO) {
		dev_info(sm5443->dev, "%s: voltage cannot be changed during FPDO DC.", __func__);
		return -EINVAL;
	}

	if (sm5443->target_vbat != vbat || state < SM_DC_CHECK_VBAT) {
		sm5443->target_vbat = vbat;
		ret = sm_dc_set_target_vbat(sm_dc, sm5443->target_vbat);
		if ((sm_dc != wpc_dc) && (wpc_dc->state < SM_DC_CHECK_VBAT))
			sm_dc_set_target_vbat(wpc_dc, sm5443->target_vbat);
	}

	return ret;
}

static int psy_chg_set_chg_curr(struct sm5443_charger *sm5443, int ibat)
{
	int ret = 0;

	dev_info(sm5443->dev, "%s: dldn't support cc_loop\n", __func__);
	sm5443->target_ibat = ibat;

	return ret;
}

static int psy_chg_set_input_curr(struct sm5443_charger *sm5443, int ibus)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	struct sm_dc_info *wpc_dc = sm5443->wpc_dc;
	int state = sm_dc_get_current_state(sm_dc);
	u32 prev_ibus = sm5443->target_ibus;
	int ret = 0;

	dev_info(sm5443->dev, "%s: ibus [%dmA] to [%dmA]\n", __func__, sm5443->target_ibus, ibus);

	if (state == SM_DC_CV_FPDO) {
		dev_info(sm5443->dev, "%s: ibus cannot be changed during FPDO DC.", __func__);
		return -EINVAL;
	}

	if (sm5443->target_ibus != ibus || state < SM_DC_CHECK_VBAT) {
		sm5443->target_ibus = ibus;
		if (sm5443->ps_type == SM_DC_POWER_SUPPLY_WPC) {
			if ((state == SM_DC_CV) && (prev_ibus + 50 == ibus)) {
				/* Thermal recovery ibus is not allowed in CV state. */
				dev_info(sm5443->dev, "%s: ibus cannot be changed in CV state.", __func__);
				return -EINVAL;
			}
			if (sm5443->target_ibus < SM5443_WPC_MIN_CURRENT) {
				dev_info(sm5443->dev, "%s: can't used less then ta_min_current(%dmA)\n",
					__func__, SM5443_WPC_MIN_CURRENT);
				sm5443->target_ibus = SM5443_WPC_MIN_CURRENT;
			}
		} else {
			if (sm5443->target_ibus < SM5443_TA_MIN_CURRENT) {
				dev_info(sm5443->dev, "%s: can't used less then ta_min_current(%dmA)\n",
					__func__, SM5443_TA_MIN_CURRENT);
				sm5443->target_ibus = SM5443_TA_MIN_CURRENT;
			}
		}
		ret = sm_dc_set_target_ibus(sm_dc, sm5443->target_ibus);
		if ((sm_dc != wpc_dc) && (wpc_dc->state < SM_DC_CHECK_VBAT))
			sm_dc_set_target_ibus(wpc_dc, sm5443->target_ibus);
	}

	return ret;
}

static int psy_chg_set_const_chg_voltage_max(struct sm5443_charger *sm5443, int max_vbat)
{
	struct sm_dc_info *pps_dc = sm5443->pps_dc;
	struct sm_dc_info *wpc_dc = sm5443->wpc_dc;

	dev_info(sm5443->dev, "%s: max_vbat [%dmV] to [%dmV]\n",
		__func__, sm5443->max_vbat, max_vbat);

	sm5443->max_vbat = max_vbat;
	pps_dc->config.chg_float_voltage = max_vbat;
	wpc_dc->config.chg_float_voltage = max_vbat;

	return 0;
}

static int psy_chg_set_opmode_ratio(struct sm5443_charger *sm5443, u8 op_mode)
{
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int state = sm_dc_get_current_state(sm_dc);
	int ret = 0;

	dev_info(sm5443->dev, "%s: [%d:1] to [%d:1]\n",
		__func__, sm5443->op_mode_ratio, op_mode);

	if (state == SM_DC_CV_FPDO) {
		dev_info(sm5443->dev, "%s: opmode cannot be changed during FPDO DC.", __func__);
		return -EINVAL;
	}
	if (sm5443->ps_type == SM_DC_POWER_SUPPLY_WPC) {
		dev_info(sm5443->dev, "%s: opmode cannot be changed in wireless DC.", __func__);
		return -EINVAL;
	}

	if (sm5443->op_mode_ratio != op_mode || state < SM_DC_CHECK_VBAT) {
		sm5443->op_mode_ratio = op_mode;
		ret = sm_dc_set_op_mode_ratio(sm_dc, sm5443->op_mode_ratio);
	}

	return 0;
}

static int psy_chg_ext_wdt_control(struct sm5443_charger *sm5443, int wdt_control)
{
	if (wdt_control)
		sm5443->wdt_disable = 1;
	else
		sm5443->wdt_disable = 0;

	dev_info(sm5443->dev, "%s: wdt_disable=%d\n", __func__, sm5443->wdt_disable);

	return 0;
}

static int sm5443_chg_set_property(struct power_supply *psy,
	enum power_supply_property psp, const union power_supply_propval *val)
{
	struct sm5443_charger *sm5443 = power_supply_get_drvdata(psy);
	enum power_supply_ext_property ext_psp =
		(enum power_supply_ext_property) psp;

	int ret = 0;

	dev_info(sm5443->dev, "%s: psp=%d, val-intval=%d\n", __func__, psp, val->intval);

	if (atomic_read(&sm5443->shutdown_cnt) > 0) {
		dev_info(sm5443->dev, "%s: DC already shutdown\n", __func__);
		return -EINVAL;
	}

	switch ((int)psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		psy_chg_set_online(sm5443, val->intval);
		break;
	case POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE:
		ret = psy_chg_set_const_chg_voltage(sm5443, val->intval);
		break;
	case POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE_MAX:
		ret = psy_chg_set_const_chg_voltage_max(sm5443, val->intval);
		break;
	case POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT:
		ret = psy_chg_set_chg_curr(sm5443, val->intval);
		break;
	case POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT:
		ret = psy_chg_set_input_curr(sm5443, val->intval);
		break;
	case POWER_SUPPLY_EXT_PROP_MIN ... POWER_SUPPLY_EXT_PROP_MAX:
		switch (ext_psp) {
		case POWER_SUPPLY_EXT_PROP_DIRECT_WDT_CONTROL:
			ret = psy_chg_ext_wdt_control(sm5443, val->intval);
			break;
		case POWER_SUPPLY_EXT_PROP_CHARGING_ENABLED:
			if (val->intval)
				ret = sm5443_start_charging(sm5443);
			else
				ret = sm5443_stop_charging(sm5443);
			sm5443_print_regmap(sm5443);
			break;
		case POWER_SUPPLY_EXT_PROP_DC_OP_MODE:
			if (val->intval == DC_MODE_2TO1)
				ret = psy_chg_set_opmode_ratio(sm5443, OP_MODE_FW_BOOST);
			else if (val->intval == DC_MODE_3TO1)
				ret = psy_chg_set_opmode_ratio(sm5443, OP_MODE_FW_3TO1);
			else
				ret = psy_chg_set_opmode_ratio(sm5443, OP_MODE_FW_BOOST);
			break;
		case POWER_SUPPLY_EXT_PROP_DIRECT_CURRENT_MAX:
			ret = psy_chg_set_input_curr(sm5443, val->intval);
			break;
		case POWER_SUPPLY_EXT_PROP_DIRECT_ADC_CTRL:
			if (val->intval)
				sm5443_enable_adc_oneshot(sm5443, 1);
			else
				sm5443_enable_adc_oneshot(sm5443, 0);
			pr_info("%s: ADC_CTRL : %d\n", __func__, val->intval);
			break;

		case POWER_SUPPLY_EXT_PROP_PASS_THROUGH_MODE:
			pr_info("[PASS_THROUGH] %s: called\n", __func__);
			if (val->intval)
				ret = sm5443_start_pass_through_charging(sm5443);
			else
				ret = sm5443_stop_charging(sm5443);
			break;

		case POWER_SUPPLY_EXT_PROP_PASS_THROUGH_MODE_TA_VOL:
			pr_info("[PASS_THROUGH_VOL] %s: called\n", __func__);
			sm5443_set_pass_through_ta_vol(sm5443, val->intval);
			break;

		case POWER_SUPPLY_EXT_PROP_D2D_REVERSE_VOLTAGE:
			if (val->intval)
				ret = sm5443_reverse_boost_enable(sm5443, OP_MODE_REV_BOOST);
			else
				ret = sm5443_reverse_boost_enable(sm5443, 0);
			break;

		case POWER_SUPPLY_EXT_PROP_DC_REVERSE_MODE:
			if (val->intval == POWER_SUPPLY_DC_REVERSE_1TO2)
				ret = sm5443_reverse_boost_enable(sm5443, OP_MODE_REV_BOOST);
			else if (val->intval == POWER_SUPPLY_DC_REVERSE_BYP)
				ret = sm5443_reverse_boost_enable(sm5443, OP_MODE_REV_BYPASS);
			else if (val->intval == 3) /* POWER_SUPPLY_DC_REVERSE_1TO3 */
				ret = sm5443_reverse_boost_enable(sm5443, OP_MODE_REV_1TO3);
			else
				ret = sm5443_reverse_boost_enable(sm5443, 0);
			break;

		default:
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	if (ret < 0)
		return ret;

	return 0;
}

static char *sm5443_supplied_to[] = {
	"sm5443-charger",
};

static enum power_supply_property sm5443_charger_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
};

static const struct power_supply_desc sm5443_charger_power_supply_desc = {
	.name		= "sm5443-charger",
	.type		= POWER_SUPPLY_TYPE_UNKNOWN,
	.get_property	= sm5443_chg_get_property,
	.set_property	= sm5443_chg_set_property,
	.properties	= sm5443_charger_props,
	.num_properties	= ARRAY_SIZE(sm5443_charger_props),
};

static const struct power_supply_desc sm5443_charger_power_supply_sub_desc = {
	.name		= "sm5443-charger-sub",
	.type		= POWER_SUPPLY_TYPE_UNKNOWN,
	.get_property	= sm5443_chg_get_property,
	.set_property	= sm5443_chg_set_property,
	.properties	= sm5443_charger_props,
	.num_properties	= ARRAY_SIZE(sm5443_charger_props),
};

static int sm5443_get_adc_value(struct i2c_client *i2c, u8 adc_ch)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);
	int adc;

	switch (adc_ch) {
	case SM_DC_ADC_THEM:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_THEM);
		break;
	case SM_DC_ADC_DIETEMP:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_TDIE);
		break;
	case SM_DC_ADC_VBAT:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_VBAT);
		break;
	case SM_DC_ADC_VBUS:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_VBUS);
		break;
	case SM_DC_ADC_IBUS:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_IBUS);
		break;
	case SM_DC_ADC_VOUT:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_VOUT);
		break;
	case SM_DC_ADC_VEXT1:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_VEXT1);
		break;
	case SM_DC_ADC_VEXT2:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_VEXT2);
		break;
	case SM_DC_ADC_PMID:
		adc = sm5443_convert_adc(sm5443, SM5443_ADC_PMID);
		break;
	default:
		adc = 0;
		break;
	}

	return adc;
}

static int sm5443_get_charging_enable(struct i2c_client *i2c)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);

	return sm5443_check_charging_enable(sm5443);
}

static int sm5443_set_charging_enable(struct i2c_client *i2c, bool enable)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);

	if (enable)
		sm5443_set_op_mode(sm5443, sm_dc->op_mode_ratio);
	else
		sm5443_set_op_mode(sm5443, OP_MODE_INIT);


	sm5443_print_regmap(sm5443);

	return 0;
}

static int sm5443_dc_set_charging_config(struct i2c_client *i2c, u32 cv_gl, u32 ci_gl, u8 op_mode)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	u32 vbatreg, ibuslim, freq;

	if (sm_dc_get_current_state(sm_dc) <= SM_DC_UPDAT_BAT) {
		vbatreg = SM5443_PRESET_VBATREG; /* set 4450mV VBATREG in preset & precc state */
	} else if (sm_dc_get_current_state(sm_dc) == SM_DC_CV_FPDO) {
		vbatreg = cv_gl;
	} else {
		if (sm5443->pdata->en_vbatreg)
			vbatreg = cv_gl;
		else
			vbatreg = cv_gl + SM5443_CV_OFFSET;
	}

	if (sm_dc_get_current_state(sm_dc) == SM_DC_CV_FPDO)
		ibuslim = ci_gl + (SM5443_CI_OFFSET * 2);
	else if (ci_gl <= SM5443_TA_MIN_CURRENT + 500)
		ibuslim = ci_gl + SM5443_CI_OFFSET;
	else
		ibuslim = ci_gl * 106 / 100;

	if (ibuslim % 50)
		ibuslim = ((ibuslim / 50) * 50) + 50;

	if (op_mode == OP_MODE_FW_3TO1)
		freq = sm5443->pdata->freq[2];
	else if (op_mode == OP_MODE_FW_BOOST)
		freq = sm5443->pdata->freq[1];
	else
		freq = sm5443->pdata->freq[0];

	sm5443_set_ibuslim(sm5443, ibuslim);
	sm5443_set_vbatreg(sm5443, vbatreg);
	sm5443_set_freq(sm5443, freq);

	pr_info("%s %s: vbat_reg=%dmV, ibus_lim=%dmA, freq=%dkHz\n", sm_dc->name,
		__func__, vbatreg, ibuslim, freq);

	return 0;
}

static int sm5443_send_pd_msg(struct i2c_client *i2c, struct sm_dc_power_source_info *ta)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int ret;

	if (sm5443->ta_type == SM5443_TA_USBPD_2P0) {
		pr_err("%s %s: ta_type is fpdo, skip pd_select_pps\n", sm_dc->name, __func__);
		return 0;
	}

	mutex_lock(&sm5443->pd_lock);

	ret = sec_pd_select_pps(ta->pdo_pos, ta->v, ta->c);
	if (ret == -EBUSY) {
		pr_info("%s %s: request again\n", sm_dc->name, __func__);
		msleep(100);
		ret = sec_pd_select_pps(ta->pdo_pos, ta->v, ta->c);
	}

	mutex_unlock(&sm5443->pd_lock);

	return ret;
	}

static int sm5443_get_apdo_max_power(struct i2c_client *i2c, struct sm_dc_power_source_info *ta)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	int ret;

	ta->pdo_pos = 0;    /* set '0' else return error */
	ta->c_max = 0;
	ta->p_max = 0;
	if (sm_dc->op_mode_ratio == OP_MODE_FW_3TO1)
		ta->v_max = SM_DC_3TO1_TA_MAX_VOL; /* request voltage level */
	else
		ta->v_max = SM_DC_2TO1_TA_MAX_VOL;

	ret = sec_pd_get_apdo_max_power(&ta->pdo_pos, &ta->v_max, &ta->c_max, &ta->p_max);
	if (ret < 0) {
		dev_err(sm5443->dev, "%s: error:sec_pd_get_apdo_max_power\n", __func__);
	} else {
		sm_dc->ta.pdo_pos = ta->pdo_pos;
		sm_dc->ta.v_max = ta->v_max;
		sm_dc->ta.c_max = ta->c_max;
		sm_dc->ta.p_max = ta->p_max;
		if (ta->v_max < SM_DC_1TO1_TA_MAX_VOL) { /* 1x conversion ratio */
			sm_dc->op_mode_ratio = OP_MODE_FW_BYPASS;
		} else if (ta->v_max <= SM_DC_2TO1_TA_MAX_VOL) { /* 2x conversion ratio */
			if (sm_dc->op_mode_ratio != OP_MODE_FW_BOOST) {
				dev_err(sm5443->dev, "%s: error: check the apdo max power(2)\n", __func__);
				return -EINVAL;
			}
		}
	}

	dev_info(sm5443->dev,
			"%s: pdo_pos:%d, max_vol:%dmV, max_cur:%dmA, max_pwr:%dmW\n",
			__func__, ta->pdo_pos, ta->v_max, ta->c_max, ta->p_max);
	return ret;
}


static int sm5443_update_dc_vbatreg(struct i2c_client *i2c, u32 cv_gl, bool is_preset)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	u32 vbatreg;

	vbatreg = sm5443_get_vbatreg(sm5443);

	if (is_preset) {
		if (vbatreg != SM5443_PRESET_VBATREG) {
			pr_info("%s %s: [%dmV] to [%dmV]\n", sm_dc->name,
			__func__, vbatreg, SM5443_PRESET_VBATREG);
			vbatreg = SM5443_PRESET_VBATREG;
			sm5443_set_vbatreg(sm5443, vbatreg);
		}
	} else if (sm5443->pdata->en_vbatreg) {
		if (vbatreg != cv_gl) {
			pr_info("%s %s: [%dmV] to [%dmV]\n", sm_dc->name,
			__func__, vbatreg, cv_gl);
			vbatreg = cv_gl;
			sm5443_set_vbatreg(sm5443, vbatreg);
		}
	} else {
		if (vbatreg != cv_gl + SM5443_CV_OFFSET) {
			pr_info("%s %s: [%dmV] to [%dmV]\n", sm_dc->name,
			__func__, vbatreg, cv_gl + SM5443_CV_OFFSET);
			vbatreg = cv_gl + SM5443_CV_OFFSET;
			sm5443_set_vbatreg(sm5443, vbatreg);
		}
	}
	return 0;
};

static const struct sm_dc_ops sm5443_dc_pps_ops = {
	.get_adc_value          = sm5443_get_adc_value,
	.set_adc_mode           = sm5443_set_adc_mode,
	.get_charging_enable    = sm5443_get_charging_enable,
	.get_dc_flag_status     = sm5443_get_dc_flag_status,
	.set_charging_enable    = sm5443_set_charging_enable,
	.set_charging_config    = sm5443_dc_set_charging_config,
	.send_power_source_msg  = sm5443_send_pd_msg,
	.get_apdo_max_power     = sm5443_get_apdo_max_power,
	.update_dc_vbatreg      = sm5443_update_dc_vbatreg,
};

static int sm5443_wpc_set_charging_config(struct i2c_client *i2c, u32 cv_gl, u32 ci_gl, u8 op_mode)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	u32 vbatreg, ibuslim, freq;

	vbatreg = cv_gl;

	if (ci_gl <= SM5443_TA_MIN_CURRENT + 500)
		ibuslim = ci_gl + SM5443_CI_OFFSET;
	else
		ibuslim = ci_gl * 106 / 100;

	if (ibuslim % 50)
		ibuslim = ((ibuslim / 50) * 50) + 50;

	if (op_mode == OP_MODE_FW_3TO1)
		freq = sm5443->pdata->freq[2];
	else if (op_mode == OP_MODE_FW_BOOST)
		freq = sm5443->pdata->freq[1];
	else
		freq = sm5443->pdata->freq[0];

	sm5443_set_ibuslim(sm5443, ibuslim);
	sm5443_set_vbatreg(sm5443, vbatreg);
	sm5443_set_freq(sm5443, freq);

	pr_info("%s %s: vbat_reg=%dmV, ibus_lim=%dmA, freq=%dkHz\n", sm_dc->name,
		__func__, vbatreg, ibuslim, freq);

	return 0;
}

static int sm5443_send_wpc_msg(struct i2c_client *i2c, struct sm_dc_power_source_info *ta)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);
	struct power_supply *psy;
	union power_supply_propval pro_val = {0, };
	int ret;

	if (sm5443->ta_type != SM5443_TA_WIRELESS) {
		dev_err(sm5443->dev, "%s: error: ta_type is not wireless\n", __func__);
		return -EINVAL;
	}

	mutex_lock(&sm5443->pd_lock);

	pr_info("%s: vol=%d\n", __func__, ta->v);
	psy = power_supply_get_by_name("wireless");
	if (!psy) {
		dev_err(sm5443->dev, "Cannot find wireless power supply\n");
		ret = -ENODEV;
		goto out;
	}

	pro_val.intval = ta->v;
	ret = power_supply_set_property(psy,
		(enum power_supply_property)POWER_SUPPLY_EXT_PROP_WC_SELECT_PPS, &pro_val);
	power_supply_put(psy);
	if (ret < 0) {
		dev_err(sm5443->dev, "Cannot set voltage\n");
		ret = -ENODEV;
		goto out;
	}

out:
	mutex_unlock(&sm5443->pd_lock);

	return ret;
}

static const struct sm_dc_ops sm5443_dc_wpc_ops = {
	.get_adc_value          = sm5443_get_adc_value,
	.set_adc_mode           = sm5443_set_adc_mode,
	.get_charging_enable    = sm5443_get_charging_enable,
	.get_dc_flag_status     = sm5443_get_dc_flag_status,
	.set_charging_enable    = sm5443_set_charging_enable,
	.set_charging_config    = sm5443_wpc_set_charging_config,
	.send_power_source_msg  = sm5443_send_wpc_msg,
	.get_apdo_max_power     = sm5443_get_apdo_max_power,
	.update_dc_vbatreg      = sm5443_update_dc_vbatreg,
};

static irqreturn_t sm5443_irq_thread(int irq, void *data)
{
	struct sm5443_charger *sm5443 = (struct sm5443_charger *)data;
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	u8 op_mode = sm5443_get_op_mode(sm5443);
	u8 flag1, flag2, flag3, flag4, flag5, flag6, flag7;
	u32 err = 0x0;

	sm5443_read_reg(sm5443, SM5443_REG_FLAG1, &flag1);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG2, &flag2);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG3, &flag3);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG4, &flag4);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG5, &flag5);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG6, &flag6);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG7, &flag7);
	dev_info(sm5443->dev, "%s: FLAG:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x:0x%x\n",
		__func__, flag1, flag2, flag3, flag4, flag5, flag6, flag7);

	/* check forced CUT-OFF status */
	if (sm_dc_get_current_state(sm_dc) > SM_DC_PRESET &&
		op_mode == OP_MODE_INIT) {
		if (flag1 & SM5443_FLAG1_VINOVP)
			err += SM_DC_ERR_VINOVP;

		if (flag1 & SM5443_FLAG1_IBUSOCP)
			err += SM_DC_ERR_IBUSOCP;

		if (flag1 & SM5443_FLAG1_IBUSUCP)
			err += SM_DC_ERR_IBUSUCP;

		if (flag2 & SM5443_FLAG2_VBATOVP)
			err += SM_DC_ERR_VBATOVP;

		if (flag2 & SM5443_FLAG2_TSD)
			err += SM_DC_ERR_TSD;

		if (flag2 & SM5443_FLAG2_VIN2OUTOVP)
			err += SM_DC_ERR_VIN2OUTOVP;

		if (flag2 & SM5443_FLAG2_VIN2OUTUVP)
			err += SM_DC_ERR_VIN2OUTUVP;

		if (flag2 & SM5443_FLAG2_CNSHTP)
			err += SM_DC_ERR_CN_SHORT;

		if (flag3 & SM5443_FLAG3_VINUVLO)
			err += SM_DC_ERR_VINUVLO;

		dev_err(sm5443->dev, "%s: forced charge cut-off(err=0x%x)\n", __func__, err);
		sm_dc_report_error_status(sm_dc, err);
	}

	if (flag2 & SM5443_FLAG2_VBATREG) {
		dev_info(sm5443->dev, "%s: VBATREG detected\n", __func__);
		sm_dc_report_interrupt_event(sm_dc, SM_DC_INT_VBATREG);
	}

	if (flag4 & SM5443_FLAG4_IBUSREG)
		dev_info(sm5443->dev, "%s: IBUSREG detected\n", __func__);

	if (flag3 & SM5443_FLAG3_VINPOK)
		dev_info(sm5443->dev, "%s: VINPOK detected\n", __func__);

	if (flag3 & SM5443_FLAG3_VINUVLO)
		dev_info(sm5443->dev, "%s: VINUVLO detected\n", __func__);

	if (flag3 & SM5443_FLAG3_WTDTMR) {
		dev_info(sm5443->dev, "%s: Watchdog Timer expired\n", __func__);
		sm_dc_report_interrupt_event(sm_dc, SM_DC_INT_WDTOFF);
	}

	dev_info(sm5443->dev, "closed %s\n", __func__);

	return IRQ_HANDLED;
}

static int sm5443_irq_init(struct sm5443_charger *sm5443)
{
	int ret;
	u8 reg;

	sm5443->irq = gpio_to_irq(sm5443->pdata->irq_gpio);
	dev_info(sm5443->dev, "%s: irq_gpio=%d, irq=%d\n", __func__,
	sm5443->pdata->irq_gpio, sm5443->irq);

	ret = gpio_request(sm5443->pdata->irq_gpio, "sm5540_irq");
	if (ret) {
		dev_err(sm5443->dev, "%s: fail to request gpio(ret=%d)\n",
			__func__, ret);
		return ret;
	}
	gpio_direction_input(sm5443->pdata->irq_gpio);
	gpio_free(sm5443->pdata->irq_gpio);

	sm5443_write_reg(sm5443, SM5443_REG_FLAGMSK1, 0xE2);
	sm5443_write_reg(sm5443, SM5443_REG_FLAGMSK2, 0x00);
	sm5443_write_reg(sm5443, SM5443_REG_FLAGMSK3, 0xD6);
	sm5443_write_reg(sm5443, SM5443_REG_FLAGMSK4, 0xDA);
	sm5443_write_reg(sm5443, SM5443_REG_FLAGMSK5, 0x00);
	sm5443_write_reg(sm5443, SM5443_REG_FLAGMSK6, 0x00);
	sm5443_write_reg(sm5443, SM5443_REG_FLAGMSK7, 0x00);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG1, &reg);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG2, &reg);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG3, &reg);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG4, &reg);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG5, &reg);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG6, &reg);
	sm5443_read_reg(sm5443, SM5443_REG_FLAG7, &reg);

	ret = request_threaded_irq(sm5443->irq, NULL, sm5443_irq_thread,
		IRQF_TRIGGER_LOW | IRQF_ONESHOT,
		"sm5443-irq", sm5443);
	if (ret) {
		dev_err(sm5443->dev, "%s: fail to request irq(ret=%d)\n",
			__func__, ret);
		return ret;
	}

	return 0;
}

static int sm5443_hw_init_config(struct sm5443_charger *sm5443)
{
	int ret;
	u8 reg;

	/* check to valid I2C transfer & register control */
	ret = sm5443_read_reg(sm5443, SM5443_REG_DEVICE_ID, &reg);
	if (ret < 0 || (reg & 0xF) != 0x1) {
		dev_err(sm5443->dev, "%s: device not found on this channel (reg=0x%x)\n",
			__func__, reg);
		return -ENODEV;
	}
	sm5443->pdata->rev_id = (reg >> 4) & 0xf;

	sm5443_init_reg_param(sm5443);
#if IS_ENABLED(CONFIG_BATTERY_SAMSUNG)
	psy_chg_set_const_chg_voltage(sm5443, sm5443->pdata->battery.chg_float_voltage);
	sm5443_reverse_boost_enable(sm5443, 0);
#endif

	return 0;
}

#if defined(CONFIG_OF)
static int sm5443_charger_parse_dt(struct device *dev,
									struct sm5443_platform_data *pdata)
{
	struct device_node *np_sm5443 = dev->of_node;
	struct device_node *np_battery;
	int ret;

	/* Parse: sm5443 node */
	if (!np_sm5443) {
		dev_err(dev, "%s: empty of_node for sm5443_dev\n", __func__);
		return -EINVAL;
	}
	pdata->irq_gpio = of_get_named_gpio(np_sm5443, "sm5443,irq-gpio", 0);
	dev_info(dev, "parse_dt: irq_gpio=%d\n", pdata->irq_gpio);

	ret = of_property_read_u32(np_sm5443, "sm5443,r_ttl", &pdata->r_ttl);
	if (ret) {
		dev_info(dev, "%s: sm5443,r_ttl is Empty\n", __func__);
		pdata->r_ttl = 320000;
	}
	dev_info(dev, "parse_dt: r_ttl=%d\n", pdata->r_ttl);

	ret = of_property_read_u32_array(np_sm5443, "sm5443,freq", pdata->freq, 3);
	if (ret) {
		dev_info(dev, "%s: sm5443,freq is Empty\n", __func__);
		pdata->freq[0] = 400;
		pdata->freq[1] = 500;
		pdata->freq[2] = 700;
	}
	dev_info(dev, "parse_dt: freq_byp=%dkHz, freq_2to1=%dkHz, freq_3to1=%dkHz\n",
		pdata->freq[0], pdata->freq[1], pdata->freq[2]);

	ret = of_property_read_u32(np_sm5443, "sm5443,freq_fpdo", &pdata->freq_fpdo);
	if (ret) {
		dev_info(dev, "%s: sm5443,freq_fpdo is Empty\n", __func__);
		pdata->freq_fpdo = 500;
	}
	dev_info(dev, "parse_dt: freq_fpdo=%dkHz\n", pdata->freq_fpdo);

	ret = of_property_read_u32_array(np_sm5443, "sm5443,freq_siop", pdata->freq_siop, 2);
	if (ret) {
		dev_info(dev, "%s: sm5443,freq_siop is Empty\n", __func__);
		pdata->freq_siop[0] = 500;
		pdata->freq_siop[1] = 700;
	}
	dev_info(dev, "parse_dt: freq_siop=%dkHz, %dkHz\n",
		pdata->freq_siop[0], pdata->freq_siop[1]);

	ret = of_property_read_u32(np_sm5443, "sm5443,topoff", &pdata->topoff);
	if (ret) {
		dev_info(dev, "%s: sm5443,topoff is Empty\n", __func__);
		pdata->topoff = 900;
	}
	dev_info(dev, "parse_dt: topoff=%d\n", pdata->topoff);

	ret = of_property_read_u32(np_sm5443, "sm5443,wc_topoff", &pdata->wc_topoff);
	if (ret) {
		dev_info(dev, "%s: sm5443,wc_topoff is Empty\n", __func__);
		pdata->wc_topoff = 380;
	}
	dev_info(dev, "parse_dt: wc_topoff=%d\n", pdata->wc_topoff);

	ret = of_property_read_u32(np_sm5443, "sm5443,en_vbatreg", &pdata->en_vbatreg);
	if (ret) {
		dev_info(dev, "%s: sm5443,en_vbatreg is Empty\n", __func__);
		pdata->en_vbatreg = 0;
	}
	dev_info(dev, "parse_dt: en_vbatreg=%d\n", pdata->en_vbatreg);

	ret = of_property_read_u32(np_sm5443, "sm5443,fpdo_topoff", &pdata->fpdo_topoff);
	if (ret) {
		pr_info("%s: sm5443,fpdo_topoff is Empty\n", __func__);
		pdata->fpdo_topoff = 1700000; /* 1700mA */
	}
	pr_info("%s: sm5443,fpdo_topoff is %d\n", __func__, pdata->fpdo_topoff);

	ret = of_property_read_u32(np_sm5443, "sm5443,fpdo_mainvbat_reg", &pdata->fpdo_mainvbat_reg);
	if (ret) {
		pr_info("%s: sm5443,fpdo_mainvbat_reg is Empty\n", __func__);
		pdata->fpdo_mainvbat_reg = 4230000; /* 4230mV */
	}
	pr_info("%s: sm5443,fpdo_mainvbat_reg is %d\n", __func__, pdata->fpdo_mainvbat_reg);

	ret = of_property_read_u32(np_sm5443, "sm5443,fpdo_subvbat_reg", &pdata->fpdo_subvbat_reg);
	if (ret) {
		pr_info("%s: sm5443,fpdo_subvbat_reg is Empty\n", __func__);
		pdata->fpdo_subvbat_reg = 4200000; /* 4200mV */
	}
	pr_info("%s: sm5443,fpdo_subvbat_reg is %d\n", __func__, pdata->fpdo_subvbat_reg);

	ret = of_property_read_u32(np_sm5443, "sm5443,fpdo_vnow_reg", &pdata->fpdo_vnow_reg);
	if (ret) {
		pr_info("%s: sm5443,fpdo_vnow_reg is Empty\n", __func__);
		pdata->fpdo_vnow_reg = 5000000; /* 5000mV means disable */
	}
	pr_info("%s: sm5443,fpdo_vnow_reg is %d\n", __func__, pdata->fpdo_vnow_reg);

	ret = of_property_read_u32(np_sm5443, "sm5443,init_pps_c_rate", &pdata->init_pps_c_rate);
	if (ret) {
		pr_info("%s: sm5443,init_pps_c_rate is Empty\n", __func__);
		pdata->init_pps_c_rate = 95; /* 95% pps_c of iin */
	}
	pr_info("%s: sm5443,init_pps_c_rate is %d\n", __func__, pdata->init_pps_c_rate);

	/* Parse: battery node */
	np_battery = of_find_node_by_name(NULL, "battery");
	if (!np_battery) {
		dev_err(dev, "%s: empty of_node for battery\n", __func__);
		return -EINVAL;
	}
	ret = of_property_read_u32(np_battery, "battery,chg_float_voltage",
		&pdata->battery.chg_float_voltage);
	if (ret) {
		dev_info(dev, "%s: battery,chg_float_voltage is Empty\n", __func__);
		pdata->battery.chg_float_voltage = 4200;
	}
	ret = of_property_read_string(np_battery, "battery,charger_name",
		(char const **)&pdata->battery.sec_dc_name);
	if (ret) {
		dev_info(dev, "%s: battery,charger_name is Empty\n", __func__);
		pdata->battery.sec_dc_name = "sec-direct-charger";
	}
	ret = of_property_read_string(np_battery, "battery,fuelgauge_name",
		(char const **)&pdata->battery.fuelgauge_name);
	if (ret) {
		dev_info(dev, "%s: battery,fuelgauge_name is Empty\n", __func__);
		pdata->battery.fuelgauge_name = "sec-fuelgauge";
	}
	ret = of_property_read_u32(np_battery, "battery,fpdo_dc_charge_power",
		&pdata->battery.fpdo_chg_curr);
	pdata->battery.fpdo_chg_curr /= 9; /* power to current */
	if (ret) {
		dev_info(dev, "%s: battery,fpdo_dc_charge_power is Empty\n", __func__);
		pdata->battery.fpdo_chg_curr = 10000; /* 10A */
	}

	dev_info(dev,
	"parse_dt: float_v=%d, sec_dc_name=%s, fuelgauge_name=%s, fpdo_chg_curr=%dmA\n",
	pdata->battery.chg_float_voltage, pdata->battery.sec_dc_name,
	pdata->battery.fuelgauge_name, pdata->battery.fpdo_chg_curr);

	return 0;
}
#endif  /* CONFIG_OF */

enum {
	ADDR = 0,
	SIZE,
	DATA,
	UPDATE,
	TA_MIN,
};
static ssize_t chg_show_attrs(struct device *dev,
	struct device_attribute *attr, char *buf);
static ssize_t chg_store_attrs(struct device *dev,
	struct device_attribute *attr,
const char *buf, size_t count);
#define CHARGER_ATTR(_name)				\
{							\
	.attr = {.name = #_name, .mode = 0660},	\
	.show = chg_show_attrs,			\
	.store = chg_store_attrs,			\
}
static struct device_attribute charger_attrs[] = {
	CHARGER_ATTR(addr),
	CHARGER_ATTR(size),
	CHARGER_ATTR(data),
	CHARGER_ATTR(update),
	CHARGER_ATTR(ta_min_v),
};
static int chg_create_attrs(struct device *dev)
{
	int i, rc;

	for (i = 0; i < (int)ARRAY_SIZE(charger_attrs); i++) {
		rc = device_create_file(dev, &charger_attrs[i]);
		if (rc)
			goto create_attrs_failed;
	}
	return rc;

create_attrs_failed:
	dev_err(dev, "%s: failed (%d)\n", __func__, rc);
	while (i--)
		device_remove_file(dev, &charger_attrs[i]);
	return rc;
}

static ssize_t chg_show_attrs(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct sm5443_charger *sm5443 = dev_get_drvdata(dev->parent);
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	const ptrdiff_t offset = attr - charger_attrs;
	int i = 0;
	u8 addr;
	u8 val;

	switch (offset) {
	case ADDR:
		i += sprintf(buf, "0x%x\n", sm5443->addr);
		break;
	case SIZE:
		i += sprintf(buf, "0x%x\n", sm5443->size);
		break;
	case DATA:
		for (addr = sm5443->addr; addr < (sm5443->addr+sm5443->size); addr++) {
			sm5443_read_reg(sm5443, addr, &val);
			i += scnprintf(buf + i, PAGE_SIZE - i,
				"0x%04x : 0x%02x\n", addr, val);
		}
		break;
	case TA_MIN:
		i += sprintf(buf, "%d\n", sm_dc->config.ta_min_voltage);
		break;
	default:
		return -EINVAL;
	}
	return i;
}

static ssize_t chg_store_attrs(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct sm5443_charger *sm5443 = dev_get_drvdata(dev->parent);
	struct sm_dc_info *sm_dc = select_sm_dc_info(sm5443);
	const ptrdiff_t offset = attr - charger_attrs;
	int ret = 0;
	int x, y, z, k;

	switch (offset) {
	case ADDR:
		if (sscanf(buf, "0x%4x\n", &x) == 1)
			sm5443->addr = x;
		ret = count;
		break;
	case SIZE:
		if (sscanf(buf, "%5d\n", &x) == 1)
			sm5443->size = x;
		ret = count;
		break;
	case DATA:
		if (sscanf(buf, "0x%8x 0x%8x", &x, &y) == 2) {
			if ((x >= SM5443_REG_CNTL1 && x <= SM5443_REG_REG1) ||
				(x >= SM5443_REG_ADC_CNTL1 && x <= SM5443_REG_CNTL5)) {
				u8 addr = x;
				u8 data = y;

				if (sm5443_write_reg(sm5443, addr, data) < 0) {
					dev_info(sm5443->dev,
					"%s: addr: 0x%x write fail\n", __func__, addr);
				}
			} else {
				dev_info(sm5443->dev,
				"%s: addr: 0x%x is wrong\n", __func__, x);
			}
		}
		ret = count;
		break;
	case UPDATE:
		if (sscanf(buf, "0x%8x 0x%8x 0x%8x %d", &x, &y, &z, &k) == 4) {
			if ((x >= SM5443_REG_CNTL1 && x <= SM5443_REG_REG1) ||
				(x >= SM5443_REG_ADC_CNTL1 && x <= SM5443_REG_CNTL5)) {
				u8 addr = x, data = y, val = z, pos = k;

				if (sm5443_update_reg(sm5443, addr, data, val, pos)) {
					dev_info(sm5443->dev,
					"%s: addr: 0x%x write fail\n", __func__, addr);
				}
			} else {
				dev_info(sm5443->dev,
				"%s: addr: 0x%x is wrong\n", __func__, x);
			}
		}
		ret = count;
		break;
	case TA_MIN:
		if (sscanf(buf, "%5d\n", &x) == 1)
			sm_dc->config.ta_min_voltage = x;
		ret = count;
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}

static int sm5443_dbg_read_reg(void *data, u64 *val)
{
	struct sm5443_charger *sm5443 = data;
	int ret;
	u8 reg;

	ret = sm5443_read_reg(sm5443, sm5443->debug_address, &reg);
	if (ret < 0) {
		dev_err(sm5443->dev, "%s: failed read 0x%02x\n",
			__func__, sm5443->debug_address);
		return ret;
	}
	*val = reg;

	return 0;
}

static int sm5443_dbg_write_reg(void *data, u64 val)
{
	struct sm5443_charger *sm5443 = data;
	int ret;

	ret = sm5443_write_reg(sm5443, sm5443->debug_address, (u8)val);
	if (ret < 0) {
		dev_err(sm5443->dev, "%s: failed write 0x%02x to 0x%02x\n",
			__func__, (u8)val, sm5443->debug_address);
		return ret;
	}

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(register_debug_ops, sm5443_dbg_read_reg,
	sm5443_dbg_write_reg, "0x%02llx\n");

static int sm5443_create_debugfs_entries(struct sm5443_charger *sm5443)
{
	struct dentry *ent;

	sm5443->debug_root = debugfs_create_dir("charger-sm5443", NULL);
	if (!sm5443->debug_root) {
		dev_err(sm5443->dev, "%s: can't create dir\n", __func__);
		return -ENOENT;
	}

	debugfs_create_x32("address", 0644,
		sm5443->debug_root, &(sm5443->debug_address));

	ent = debugfs_create_file("data", 0644,
		sm5443->debug_root, sm5443, &register_debug_ops);
	if (!ent) {
		dev_err(sm5443->dev, "%s: can't create data\n", __func__);
		return -ENOENT;
	}

	return 0;
}

static const struct i2c_device_id sm5443_charger_id_table[] = {
	{ "sm5443-charger", .driver_data = SM5443_MAIN },
	{ "sm5443-charger-sub", .driver_data =  SM5443_SUB},
	{ }
};
MODULE_DEVICE_TABLE(i2c, sm5443_charger_id_table);

#if defined(CONFIG_OF)
static const struct of_device_id sm5443_of_match_table[] = {
	{ .compatible = "siliconmitus,sm5443", .data = (void *)SM5443_MAIN },
	{ .compatible = "siliconmitus,sm5443-sub", .data = (void *)SM5443_SUB },
	{ },
};
MODULE_DEVICE_TABLE(of, sm5443_of_match_table);
#endif /* CONFIG_OF */

#if (KERNEL_VERSION(6, 3, 0) <= LINUX_VERSION_CODE)
static int sm5443_charger_probe(struct i2c_client *i2c)
#else
static int sm5443_charger_probe(struct i2c_client *i2c,
			const struct i2c_device_id *id)
#endif
{
	struct sm5443_charger *sm5443;
	struct sm_dc_info *pps_dc, *wpc_dc;
	struct sm5443_platform_data *pdata;
	struct power_supply_config psy_cfg = {};
	const struct of_device_id *of_id;
	int ret, chip;
	u8 reg;

	dev_info(&i2c->dev, "%s: probe start\n", __func__);

	of_id = of_match_device(sm5443_of_match_table, &i2c->dev);
	if (!of_id) {
		dev_info(&i2c->dev, "sm5443-Charger matching on node name, compatible is preferred\n");
#if (KERNEL_VERSION(6, 3, 0) <= LINUX_VERSION_CODE)
		return -ENODEV;
#else
		chip = (enum sm5443_chip_id)id->driver_data;
#endif
	} else {
		chip = (enum sm5443_chip_id)of_id->data;
	}
	dev_info(&i2c->dev, "%s: chip:%d\n", __func__, chip);

	sm5443 = devm_kzalloc(&i2c->dev, sizeof(struct sm5443_charger), GFP_KERNEL);
	if (!sm5443)
		return -ENOMEM;

#if defined(CONFIG_OF)
	pdata = devm_kzalloc(&i2c->dev, sizeof(struct sm5443_platform_data), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	ret = sm5443_charger_parse_dt(&i2c->dev, pdata);
	if (ret < 0) {
		dev_err(&i2c->dev, "%s: fail to parse_dt\n", __func__);
		pdata = NULL;
	}
#else   /* CONFIG_OF */
	pdata = NULL;
#endif  /* CONFIG_OF */
	if (!pdata) {
		dev_err(&i2c->dev, "%s: we didn't support fixed platform_data yet\n", __func__);
		return -EINVAL;
	}

	/* create sm direct-charging instance for PD3.0(PPS) */
	if (chip == SM5443_SUB)
		pps_dc = sm_dc_create_pd_instance("sm5443-sub-DC", i2c);
	else
		pps_dc = sm_dc_create_pd_instance("sm5443-PD-DC", i2c);
	if (IS_ERR(pps_dc)) {
		dev_err(&i2c->dev, "%s: fail to create PD-DC module\n", __func__);
		return -ENOMEM;
	}
	pps_dc->config.ta_min_current = SM5443_TA_MIN_CURRENT;
	pps_dc->config.ta_min_voltage = 3700;
	pps_dc->config.dc_min_vbat = 3100;
	pps_dc->config.dc_vbus_ovp_th = 5400;
	pps_dc->config.r_ttl = pdata->r_ttl;
	pps_dc->config.topoff_current = pdata->topoff;
	pps_dc->config.fpdo_topoff = pdata->fpdo_topoff;
	pps_dc->config.fpdo_mainvbat_reg = pdata->fpdo_mainvbat_reg;
	pps_dc->config.fpdo_subvbat_reg = pdata->fpdo_subvbat_reg;
	pps_dc->config.fpdo_vnow_reg = pdata->fpdo_vnow_reg;
	pps_dc->config.fpdo_chg_curr = pdata->battery.fpdo_chg_curr;
	pps_dc->config.fpdo_vflot_reg = pdata->battery.chg_float_voltage;
	pps_dc->config.need_to_sw_ocp = 0;
	pps_dc->config.init_pps_c_rate = pdata->init_pps_c_rate;
	pps_dc->config.support_pd_remain = 1; /* if pdic can't support PPS remaining, plz activate it. */
	pps_dc->config.chg_float_voltage = pdata->battery.chg_float_voltage;
	pps_dc->config.sec_dc_name = pdata->battery.sec_dc_name;
	pps_dc->config.fuelgauge_name = pdata->battery.fuelgauge_name;
	pps_dc->ops = &sm5443_dc_pps_ops;
	pps_dc->chip_id = chip;
	pps_dc->err_node = SM_DC_ERR_NODE_NONE;
	ret = sm_dc_verify_configuration(pps_dc);
	if (ret < 0) {
		dev_err(&i2c->dev, "%s: fail to verify sm_dc(ret=%d)\n", __func__, ret);
		goto err_devmem;
	}
	sm5443->pps_dc = pps_dc;

	wpc_dc = sm_dc_create_wpc_instance("sm5443-WPC-DC", i2c);
	if (IS_ERR(wpc_dc)) {
		dev_err(&i2c->dev, "%s: fail to create PD-DC module\n", __func__);
		return -ENOMEM;
	}
	wpc_dc->target_vbat = 4450; // WPC default vbat
	wpc_dc->target_ibus = 1500; // WPC default ibus
	wpc_dc->op_mode_ratio = OP_MODE_FW_3TO1; // WPC default opmode
	wpc_dc->config.ta_min_current = SM5443_WPC_MIN_CURRENT;
	wpc_dc->config.ta_min_voltage = 3500;
	wpc_dc->config.dc_min_vbat = 3100;
	wpc_dc->config.dc_vbus_ovp_th = 5350;
	wpc_dc->config.r_ttl = pdata->r_ttl;
	wpc_dc->config.topoff_current = pdata->wc_topoff;
	wpc_dc->config.fpdo_topoff = pdata->fpdo_topoff;
	wpc_dc->config.fpdo_mainvbat_reg = pdata->fpdo_mainvbat_reg;
	wpc_dc->config.fpdo_subvbat_reg = pdata->fpdo_subvbat_reg;
	wpc_dc->config.fpdo_vnow_reg = pdata->fpdo_vnow_reg;
	wpc_dc->config.fpdo_chg_curr = pdata->battery.fpdo_chg_curr;
	wpc_dc->config.fpdo_vflot_reg = pdata->battery.chg_float_voltage;
	wpc_dc->config.need_to_sw_ocp = 0;
	wpc_dc->config.init_pps_c_rate = pdata->init_pps_c_rate;
	wpc_dc->config.support_pd_remain = 1;
	wpc_dc->config.chg_float_voltage = pdata->battery.chg_float_voltage;
	wpc_dc->config.sec_dc_name = pdata->battery.sec_dc_name;
	wpc_dc->config.fuelgauge_name = pdata->battery.fuelgauge_name;
	wpc_dc->ops = &sm5443_dc_wpc_ops;
	wpc_dc->chip_id = chip;
	wpc_dc->err_node = SM_DC_ERR_NODE_NONE;
	ret = sm_dc_verify_configuration(wpc_dc);
	if (ret < 0) {
		dev_err(&i2c->dev, "%s: fail to verify sm_dc(ret=%d)\n", __func__, ret);
		goto err_devmem;
	}
	sm5443->wpc_dc = wpc_dc;

	sm5443->dev = &i2c->dev;
	sm5443->i2c = i2c;
	sm5443->pdata = pdata;
	sm5443->chip_id = chip;
	sm5443->ibusocp = 0;
	sm5443->call_state = 0;
	sm5443->ps_type = SM_DC_POWER_SUPPLY_PD;
	mutex_init(&sm5443->i2c_lock);
	mutex_init(&sm5443->pd_lock);
	atomic_set(&sm5443->shutdown_cnt, 0);
	sm5443->chg_ws = wakeup_source_register(&i2c->dev, "sm5443-charger");
	i2c_set_clientdata(i2c, sm5443);

#if KERNEL_VERSION(5, 10, 0) > LINUX_VERSION_CODE
	sm5443->i2c_hid = i2c_new_dummy(i2c->adapter, SM5443_I2C_HID_ADDR);
#else
	sm5443->i2c_hid = i2c_new_dummy_device(i2c->adapter, SM5443_I2C_HID_ADDR);
#endif
	i2c_set_clientdata(sm5443->i2c_hid, sm5443);
	ret = sm5443_read_reg(sm5443, SM5443_REG_MSKDEG_OP, &reg);
	if (ret < 0 || (reg != 0x00 && reg != 0x18)) {
		dev_err(sm5443->dev, "%s: fail to read reg(ret=%d, reg=0x%02x)\n",
			__func__, ret, reg);
		goto err_devmem;
	}

	ret = sm5443_hw_init_config(sm5443);
	if (ret < 0) {
		dev_err(sm5443->dev, "%s: fail to init config(ret=%d)\n", __func__, ret);
		goto err_devmem;
	}

	psy_cfg.drv_data = sm5443;
	psy_cfg.supplied_to = sm5443_supplied_to;
	psy_cfg.num_supplicants = ARRAY_SIZE(sm5443_supplied_to);
	if (chip == SM5443_SUB)
		sm5443->psy_chg = power_supply_register(sm5443->dev,
			&sm5443_charger_power_supply_sub_desc, &psy_cfg);
	else
		sm5443->psy_chg = power_supply_register(sm5443->dev,
			&sm5443_charger_power_supply_desc, &psy_cfg);
	if (IS_ERR(sm5443->psy_chg)) {
		dev_err(sm5443->dev, "%s: fail to register psy_chg\n", __func__);
		ret = PTR_ERR(sm5443->psy_chg);
		goto err_devmem;
	}

	if (sm5443->pdata->irq_gpio >= 0) {
		ret = sm5443_irq_init(sm5443);
		if (ret < 0) {
			dev_err(sm5443->dev, "%s: fail to init irq(ret=%d)\n", __func__, ret);
			goto err_psy_chg;
		}
	} else {
		dev_warn(sm5443->dev, "%s: didn't assigned irq_gpio\n", __func__);
	}

	ret = chg_create_attrs(&sm5443->psy_chg->dev);
	if (ret)
		dev_err(sm5443->dev, "%s : Failed to create_attrs\n", __func__);

	ret = sm5443_create_debugfs_entries(sm5443);
	if (ret < 0) {
		dev_err(sm5443->dev, "%s: fail to create debugfs(ret=%d)\n", __func__, ret);
		goto err_psy_chg;
	}

	sec_chg_set_dev_init(SC_DEV_DIR_CHG);

	sm5443->valid_ic = true;

	dev_info(sm5443->dev, "%s: done. (rev_id=0x%x)[%s]\n", __func__,
		sm5443->pdata->rev_id, SM5443_DC_VERSION);

	return 0;

err_psy_chg:
	power_supply_unregister(sm5443->psy_chg);

err_devmem:
	mutex_destroy(&sm5443->i2c_lock);
	mutex_destroy(&sm5443->pd_lock);
	i2c_unregister_device(sm5443->i2c_hid);
	wakeup_source_unregister(sm5443->chg_ws);
	sm_dc_destroy_instance(sm5443->pps_dc);
	sm_dc_destroy_instance(sm5443->wpc_dc);

	return ret;
}

#if KERNEL_VERSION(6, 1, 0) > LINUX_VERSION_CODE
static int sm5443_charger_remove(struct i2c_client *i2c)
#else
static void sm5443_charger_remove(struct i2c_client *i2c)
#endif
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);

	sm5443_stop_charging(sm5443);
	sm5443_sw_reset(sm5443);

	power_supply_unregister(sm5443->psy_chg);
	i2c_unregister_device(sm5443->i2c_hid);
	mutex_destroy(&sm5443->i2c_lock);
	mutex_destroy(&sm5443->pd_lock);
	wakeup_source_unregister(sm5443->chg_ws);
	sm_dc_destroy_instance(sm5443->pps_dc);
	sm_dc_destroy_instance(sm5443->wpc_dc);

#if KERNEL_VERSION(6, 1, 0) > LINUX_VERSION_CODE
	return 0;
#endif
}

static void sm5443_charger_shutdown(struct i2c_client *i2c)
{
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);

	pr_info("%s: ++\n", __func__);

	atomic_inc(&sm5443->shutdown_cnt);
	sm5443_stop_charging(sm5443);
	sm5443_reverse_boost_enable(sm5443, 0);

	pr_info("%s: --\n", __func__);
}

#if defined(CONFIG_PM)
static int sm5443_charger_suspend(struct device *dev)
{
	struct i2c_client *i2c = container_of(dev, struct i2c_client, dev);
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);

	if (device_may_wakeup(dev))
		enable_irq_wake(sm5443->irq);

	disable_irq(sm5443->irq);

	return 0;
}

static int sm5443_charger_resume(struct device *dev)
{
	struct i2c_client *i2c = container_of(dev, struct i2c_client, dev);
	struct sm5443_charger *sm5443 = i2c_get_clientdata(i2c);

	if (device_may_wakeup(dev))
		disable_irq_wake(sm5443->irq);

	enable_irq(sm5443->irq);

	return 0;
}
#else   /* CONFIG_PM */
#define sm5443_charger_suspend		NULL
#define sm5443_charger_resume		NULL
#endif  /* CONFIG_PM */

const struct dev_pm_ops sm5443_pm_ops = {
	.suspend = sm5443_charger_suspend,
	.resume = sm5443_charger_resume,
};

static struct i2c_driver sm5443_charger_driver = {
	.driver = {
		.name = "sm5443-charger",
		.owner	= THIS_MODULE,
#if defined(CONFIG_OF)
		.of_match_table = sm5443_of_match_table,
#endif  /* CONFIG_OF */
#if defined(CONFIG_PM)
		.pm = &sm5443_pm_ops,
#endif  /* CONFIG_PM */
	},
	.probe        = sm5443_charger_probe,
	.remove       = sm5443_charger_remove,
	.shutdown     = sm5443_charger_shutdown,
	.id_table     = sm5443_charger_id_table,
};

static int __init sm5443_i2c_init(void)
{
	pr_info("sm5443-charger: %s\n", __func__);
	return i2c_add_driver(&sm5443_charger_driver);
}
module_init(sm5443_i2c_init);

static void __exit sm5443_i2c_exit(void)
{
	i2c_del_driver(&sm5443_charger_driver);
}
module_exit(sm5443_i2c_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SiliconMitus <hwangjoo.jang@SiliconMitus.com>");
MODULE_DESCRIPTION("Charger driver for SM5443");
MODULE_VERSION(SM5443_DC_VERSION);
