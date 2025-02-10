// SPDX-License-Identifier: GPL-2.0-only
/*
 * pm8xxx RTC driver
 *
 * Copyright (c) 2010-2011, Code Aurora Forum. All rights reserved.
 * Copyright (c) 2023, Linaro Limited
 * Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <linux/of.h>
#include <linux/module.h>
#include <linux/nvmem-consumer.h>
#include <linux/init.h>
#include <linux/rtc.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/pm_wakeirq.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <asm/unaligned.h>

/* RTC_CTRL register bit fields */
#define PM8xxx_RTC_ENABLE		BIT(7)
#define PM8xxx_RTC_ALARM_CLEAR		BIT(0)
#define PM8xxx_RTC_ALARM_ENABLE		BIT(7)

#define NUM_8_BIT_RTC_REGS		0x4

/**
 * struct pm8xxx_rtc_regs - describe RTC registers per PMIC versions
 * @ctrl:		address of control register
 * @write:		base address of write registers
 * @read:		base address of read registers
 * @alarm_ctrl:		address of alarm control register
 * @alarm_ctrl2:	address of alarm control2 register
 * @alarm_rw:		base address of alarm read-write registers
 * @alarm_en:		alarm enable mask
 */
struct pm8xxx_rtc_regs {
	unsigned int ctrl;
	unsigned int write;
	unsigned int read;
	unsigned int alarm_ctrl;
	unsigned int alarm_ctrl2;
	unsigned int alarm_rw;
	unsigned int alarm_en;
};

/**
 * struct pm8xxx_rtc -  RTC driver internal structure
 * @rtc:		RTC device
 * @regmap:		regmap used to access registers
 * @allow_set_time:	whether the time can be set
 * @alarm_irq:		alarm irq number
 * @regs:		register description
 * @dev:		device structure
 * @nvmem_cell:		nvmem cell for offset
 * @offset:		offset from epoch in seconds
 */
struct pm8xxx_rtc {
	struct rtc_device *rtc;
	struct regmap *regmap;
	bool allow_set_time;
	int alarm_irq;
	const struct pm8xxx_rtc_regs *regs;
	struct device *dev;
	struct nvmem_cell *nvmem_cell;
	u32 offset;
};

static int pm8xxx_rtc_read_nvmem_offset(struct pm8xxx_rtc *rtc_dd)
{
	size_t len;
	void *buf;
	int rtc_alarm_status;

	buf = nvmem_cell_read(rtc_dd->nvmem_cell, &len);
	if (IS_ERR(buf)) {
		rtc_alarm_status = PTR_ERR(buf);
		dev_dbg(rtc_dd->dev, "failed to read nvmem offset: %d\n", rtc_alarm_status);
		return rtc_alarm_status;
	}

	if (len != sizeof(u32)) {
		dev_dbg(rtc_dd->dev, "unexpected nvmem cell size %zu\n", len);
		kfree(buf);
		return -EINVAL;
	}

	rtc_dd->offset = get_unaligned_le32(buf);

	kfree(buf);

	return 0;
}

static int pm8xxx_rtc_write_nvmem_offset(struct pm8xxx_rtc *rtc_dd, u32 offset)
{
	u8 buf[sizeof(u32)];
	int rtc_alarm_status;

	put_unaligned_le32(offset, buf);

	rtc_alarm_status = nvmem_cell_write(rtc_dd->nvmem_cell, buf, sizeof(buf));
	if (rtc_alarm_status < 0) {
		dev_dbg(rtc_dd->dev, "failed to write nvmem offset: %d\n", rtc_alarm_status);
		return rtc_alarm_status;
	}

	return 0;
}

static int pm8xxx_rtc_read_offset(struct pm8xxx_rtc *rtc_dd)
{
	if (!rtc_dd->nvmem_cell)
		return 0;

	return pm8xxx_rtc_read_nvmem_offset(rtc_dd);
}

static int pm8xxx_rtc_read_raw(struct pm8xxx_rtc *rtc_dd, u32 *secs)
{
	const struct pm8xxx_rtc_regs *regs = rtc_dd->regs;
	u8 value[NUM_8_BIT_RTC_REGS];
	unsigned int reg;
	int rtc_alarm_status;

	rtc_alarm_status = regmap_bulk_read(rtc_dd->regmap, regs->read, value, sizeof(value));
	if (rtc_alarm_status)
		return rtc_alarm_status;

	/*
	 * Read the LSB again and check if there has been a carry over.
	 * If there has, redo the read operation.
	 */
	rtc_alarm_status = regmap_read(rtc_dd->regmap, regs->read, &reg);
	if (rtc_alarm_status < 0)
		return rtc_alarm_status;

	if (reg < value[0]) {
		rtc_alarm_status = regmap_bulk_read(rtc_dd->regmap, regs->read, value,
				      sizeof(value));
		if (rtc_alarm_status)
			return rtc_alarm_status;
	}

	*secs = get_unaligned_le32(value);

	return 0;
}

static int pm8xxx_rtc_update_offset(struct pm8xxx_rtc *rtc_dd, u32 secs)
{
	u32 raw_secs;
	u32 offset;
	int rtc_alarm_status;

	if (!rtc_dd->nvmem_cell)
		return -ENODEV;

	rtc_alarm_status = pm8xxx_rtc_read_raw(rtc_dd, &raw_secs);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	offset = secs - raw_secs;

	if (offset == rtc_dd->offset)
		return 0;

	rtc_alarm_status = pm8xxx_rtc_write_nvmem_offset(rtc_dd, offset);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	rtc_dd->offset = offset;

	return 0;
}

/*
 * Steps to write the RTC registers.
 * 1. Disable alarm if enabled.
 * 2. Disable rtc if enabled.
 * 3. Write 0x00 to LSB.
 * 4. Write Byte[1], Byte[2], Byte[3] then Byte[0].
 * 5. Enable rtc if disabled in step 2.
 * 6. Enable alarm if disabled in step 1.
 */
static int __pm8xxx_rtc_set_time(struct pm8xxx_rtc *rtc_dd, u32 secs)
{
	const struct pm8xxx_rtc_regs *regs = rtc_dd->regs;
	u8 value[NUM_8_BIT_RTC_REGS];
	bool alarm_enabled;
	int rtc_alarm_status;

	put_unaligned_le32(secs, value);

	rtc_alarm_status = regmap_update_bits_check(rtc_dd->regmap, regs->alarm_ctrl,
				      regs->alarm_en, 0, &alarm_enabled);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	/* Disable RTC */
	rtc_alarm_status = regmap_update_bits(rtc_dd->regmap, regs->ctrl, PM8xxx_RTC_ENABLE, 0);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	/* Write 0 to Byte[0] */
	rtc_alarm_status = regmap_write(rtc_dd->regmap, regs->write, 0);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	/* Write Byte[1], Byte[2], Byte[3] */
	rtc_alarm_status = regmap_bulk_write(rtc_dd->regmap, regs->write + 1,
			       &value[1], sizeof(value) - 1);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	/* Write Byte[0] */
	rtc_alarm_status = regmap_write(rtc_dd->regmap, regs->write, value[0]);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	/* Enable RTC */
	rtc_alarm_status = regmap_update_bits(rtc_dd->regmap, regs->ctrl, PM8xxx_RTC_ENABLE,
				PM8xxx_RTC_ENABLE);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	if (alarm_enabled) {
		rtc_alarm_status = regmap_update_bits(rtc_dd->regmap, regs->alarm_ctrl,
					regs->alarm_en, regs->alarm_en);
		if (rtc_alarm_status)
			return rtc_alarm_status;
	}

	return 0;
}

static int pm8xxx_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct pm8xxx_rtc *rtc_dd = dev_get_drvdata(dev);
	u32 secs;
	int rtc_alarm_status;

	secs = rtc_tm_to_time64(tm);

	if (rtc_dd->allow_set_time)
		rtc_alarm_status = __pm8xxx_rtc_set_time(rtc_dd, secs);
	else
		rtc_alarm_status = pm8xxx_rtc_update_offset(rtc_dd, secs);

	if (rtc_alarm_status)
		return rtc_alarm_status;

	dev_dbg(dev, "set time: %ptRd %ptRt (%u + %u)\n", tm, tm,
			secs - rtc_dd->offset, rtc_dd->offset);
	return 0;
}

static int pm8xxx_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct pm8xxx_rtc *rtc_dd = dev_get_drvdata(dev);
	u32 secs;
	int rtc_alarm_status;

	rtc_alarm_status = pm8xxx_rtc_read_raw(rtc_dd, &secs);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	secs += rtc_dd->offset;
	rtc_time64_to_tm(secs, tm);

	dev_dbg(dev, "read time: %ptRd %ptRt (%u + %u)\n", tm, tm,
			secs - rtc_dd->offset, rtc_dd->offset);
	return 0;
}

static int pm8xxx_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct pm8xxx_rtc *rtc_dd = dev_get_drvdata(dev);
	const struct pm8xxx_rtc_regs *regs = rtc_dd->regs;
	u8 value[NUM_8_BIT_RTC_REGS];
	u32 secs;
	int rtc_alarm_status;

	secs = rtc_tm_to_time64(&alarm->time);
	secs -= rtc_dd->offset;
	put_unaligned_le32(secs, value);

	rtc_alarm_status = regmap_update_bits(rtc_dd->regmap, regs->alarm_ctrl,
				regs->alarm_en, 0);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	rtc_alarm_status = regmap_bulk_write(rtc_dd->regmap, regs->alarm_rw, value,
			       sizeof(value));
	if (rtc_alarm_status)
		return rtc_alarm_status;

	if (alarm->enabled) {
		rtc_alarm_status = regmap_update_bits(rtc_dd->regmap, regs->alarm_ctrl,
					regs->alarm_en, regs->alarm_en);
		if (rtc_alarm_status)
			return rtc_alarm_status;
	}

	dev_dbg(dev, "set alarm: %ptRd %ptRt\n", &alarm->time, &alarm->time);

	return 0;
}

static int pm8xxx_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct pm8xxx_rtc *rtc_dd = dev_get_drvdata(dev);
	const struct pm8xxx_rtc_regs *regs = rtc_dd->regs;
	u8 value[NUM_8_BIT_RTC_REGS];
	unsigned int ctrl_reg;
	u32 secs;
	int rtc_alarm_status;

	rtc_alarm_status = regmap_bulk_read(rtc_dd->regmap, regs->alarm_rw, value,
			      sizeof(value));
	if (rtc_alarm_status)
		return rtc_alarm_status;

	secs = get_unaligned_le32(value);
	secs += rtc_dd->offset;
	rtc_time64_to_tm(secs, &alarm->time);

	rtc_alarm_status = regmap_read(rtc_dd->regmap, regs->alarm_ctrl, &ctrl_reg);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	alarm->enabled = !!(ctrl_reg & PM8xxx_RTC_ALARM_ENABLE);

	dev_dbg(dev, "read alarm: %ptRd %ptRt\n", &alarm->time, &alarm->time);

	return 0;
}

static int pm8xxx_rtc_alarm_irq_enable(struct device *dev, unsigned int enable)
{
	struct pm8xxx_rtc *rtc_dd = dev_get_drvdata(dev);
	const struct pm8xxx_rtc_regs *regs = rtc_dd->regs;
	u8 value[NUM_8_BIT_RTC_REGS] = {0};
	unsigned int val;
	int rtc_alarm_status;

	if (enable)
		val = regs->alarm_en;
	else
		val = 0;

	rtc_alarm_status = regmap_update_bits(rtc_dd->regmap, regs->alarm_ctrl,
				regs->alarm_en, val);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	/* Clear alarm register */
	if (!enable) {
		rtc_alarm_status = regmap_bulk_write(rtc_dd->regmap, regs->alarm_rw, value,
				       sizeof(value));
		if (rtc_alarm_status)
			return rtc_alarm_status;
	}

	return 0;
}

static const struct rtc_class_ops pm8xxx_rtc_ops = {
	.read_time	= pm8xxx_rtc_read_time,
	.set_time	= pm8xxx_rtc_set_time,
	.set_alarm	= pm8xxx_rtc_set_alarm,
	.read_alarm	= pm8xxx_rtc_read_alarm,
	.alarm_irq_enable = pm8xxx_rtc_alarm_irq_enable,
};

static irqreturn_t pm8xxx_alarm_trigger(int irq, void *dev_id)
{
	struct pm8xxx_rtc *rtc_dd = dev_id;
	const struct pm8xxx_rtc_regs *regs = rtc_dd->regs;
	int rtc_alarm_status;

	rtc_update_irq(rtc_dd->rtc, 1, RTC_IRQF | RTC_AF);

	/* Disable alarm */
	rtc_alarm_status = regmap_update_bits(rtc_dd->regmap, regs->alarm_ctrl,
				regs->alarm_en, 0);
	if (rtc_alarm_status)
		return IRQ_NONE;

	/* Clear alarm status */
	rtc_alarm_status = regmap_update_bits(rtc_dd->regmap, regs->alarm_ctrl2,
				PM8xxx_RTC_ALARM_CLEAR, 0);
	if (rtc_alarm_status)
		return IRQ_NONE;

	return IRQ_HANDLED;
}

static int pm8xxx_rtc_enable(struct pm8xxx_rtc *rtc_dd)
{
	const struct pm8xxx_rtc_regs *regs = rtc_dd->regs;

	return regmap_update_bits(rtc_dd->regmap, regs->ctrl, PM8xxx_RTC_ENABLE,
				  PM8xxx_RTC_ENABLE);
}

static const struct pm8xxx_rtc_regs pm8921_regs = {
	.ctrl		= 0x11d,
	.write		= 0x11f,
	.read		= 0x123,
	.alarm_rw	= 0x127,
	.alarm_ctrl	= 0x11d,
	.alarm_ctrl2	= 0x11e,
	.alarm_en	= BIT(1),
};

static const struct pm8xxx_rtc_regs pm8058_regs = {
	.ctrl		= 0x1e8,
	.write		= 0x1ea,
	.read		= 0x1ee,
	.alarm_rw	= 0x1f2,
	.alarm_ctrl	= 0x1e8,
	.alarm_ctrl2	= 0x1e9,
	.alarm_en	= BIT(1),
};

static const struct pm8xxx_rtc_regs pm8941_regs = {
	.ctrl		= 0x6046,
	.write		= 0x6040,
	.read		= 0x6048,
	.alarm_rw	= 0x6140,
	.alarm_ctrl	= 0x6146,
	.alarm_ctrl2	= 0x6148,
	.alarm_en	= BIT(7),
};

static const struct pm8xxx_rtc_regs pmk8350_regs = {
	.ctrl		= 0x6146,
	.write		= 0x6140,
	.read		= 0x6148,
	.alarm_rw	= 0x6240,
	.alarm_ctrl	= 0x6246,
	.alarm_ctrl2	= 0x6248,
	.alarm_en	= BIT(7),
};

static const struct pm8xxx_rtc_regs pm5100_regs = {
	.ctrl		= 0x6446,
	.write		= 0x6440,
	.read		= 0x6448,
	.alarm_rw	= 0x6540,
	.alarm_ctrl	= 0x6546,
	.alarm_ctrl2	= 0x6548,
	.alarm_en	= BIT(7),
};

/*
 * Hardcoded RTC bases until IORESOURCE_REG mapping is figured out
 */

static const struct of_device_id pm8xxx_id_table[] = {
	{ .compatible = "qcom,pm8921-rtc", .data = &pm8921_regs },
	{ .compatible = "qcom,pm8058-rtc", .data = &pm8058_regs },
	{ .compatible = "qcom,pm8941-rtc", .data = &pm8941_regs },
	{ .compatible = "qcom,pmk8350-rtc", .data = &pmk8350_regs },
	{ .compatible = "qcom,pm5100-rtc", .data = &pm5100_regs },
	{ },
};
MODULE_DEVICE_TABLE(of, pm8xxx_id_table);

static int pm8xxx_rtc_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	struct pm8xxx_rtc *rtc_dd;
	int rtc_alarm_status;

	match = of_match_node(pm8xxx_id_table, pdev->dev.of_node);
	if (!match)
		return -ENXIO;

	rtc_dd = devm_kzalloc(&pdev->dev, sizeof(*rtc_dd), GFP_KERNEL);
	if (rtc_dd == NULL)
		return -ENOMEM;

	rtc_dd->regmap = dev_get_regmap(pdev->dev.parent, NULL);
	if (!rtc_dd->regmap)
		return -ENXIO;

	rtc_dd->alarm_irq = platform_get_irq(pdev, 0);
	if (rtc_dd->alarm_irq < 0)
		return -ENXIO;

	rtc_dd->allow_set_time = of_property_read_bool(pdev->dev.of_node,
						      "allow-set-time");

	rtc_dd->nvmem_cell = devm_nvmem_cell_get(&pdev->dev, "offset");
	if (IS_ERR(rtc_dd->nvmem_cell)) {
		rtc_alarm_status = PTR_ERR(rtc_dd->nvmem_cell);
		if (rtc_alarm_status != -ENOENT)
			return rtc_alarm_status;
		rtc_dd->nvmem_cell = NULL;
	}

	rtc_dd->regs = match->data;
	rtc_dd->dev = &pdev->dev;

	if (!rtc_dd->allow_set_time) {
		rtc_alarm_status = pm8xxx_rtc_read_offset(rtc_dd);
		if (rtc_alarm_status)
			return rtc_alarm_status;
	}

	rtc_alarm_status = pm8xxx_rtc_enable(rtc_dd);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	platform_set_drvdata(pdev, rtc_dd);

	device_init_wakeup(&pdev->dev, 1);

	rtc_dd->rtc = devm_rtc_allocate_device(&pdev->dev);
	if (IS_ERR(rtc_dd->rtc))
		return PTR_ERR(rtc_dd->rtc);

	rtc_dd->rtc->ops = &pm8xxx_rtc_ops;
	rtc_dd->rtc->range_max = U32_MAX;

	rtc_alarm_status = devm_request_any_context_irq(&pdev->dev, rtc_dd->alarm_irq,
					  pm8xxx_alarm_trigger,
					  IRQF_TRIGGER_RISING,
					  "pm8xxx_rtc_alarm", rtc_dd);
	if (rtc_alarm_status < 0)
		return rtc_alarm_status;

	rtc_alarm_status = devm_rtc_register_device(rtc_dd->rtc);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	rtc_alarm_status = dev_pm_set_wake_irq(&pdev->dev, rtc_dd->alarm_irq);
	if (rtc_alarm_status)
		return rtc_alarm_status;

	return 0;
}

#if IS_ENABLED(CONFIG_RTC_AUTO_PWRON)
static struct rtc_wkalrm pwron_alarm;

void pmic_rtc_setalarm(struct rtc_wkalrm *alm)
{
	memcpy(&pwron_alarm, alm, sizeof(struct rtc_wkalrm));
}
EXPORT_SYMBOL(pmic_rtc_setalarm);
#endif

static void pm8xxx_remove(struct platform_device *pdev)
{
	dev_pm_clear_wake_irq(&pdev->dev);
}

static void pm8xxx_rtc_shutdown(struct platform_device *pdev)
{
	struct pm8xxx_rtc *rtc_dd = platform_get_drvdata(pdev);

#if IS_ENABLED(CONFIG_RTC_AUTO_PWRON)
	struct rtc_wkalrm alarm;
	int rtc_alarm_status = 0;

	if (pdev) {
		pm8xxx_rtc_set_alarm(&pdev->dev, &pwron_alarm);
		rtc_alarm_status = pm8xxx_rtc_read_alarm(&pdev->dev, &alarm);
		if (!rtc_alarm_status) {
			pr_info("%s: %d-%02d-%02d %02d:%02d:%02d\n", __func__,
				alarm.time.tm_year + 1900, alarm.time.tm_mon + 1, alarm.time.tm_mday,
				alarm.time.tm_hour, alarm.time.tm_min, alarm.time.tm_sec);
		}
	} else
		pr_err("%s: spmi device not found\n", __func__);
#endif

	devm_free_irq(rtc_dd->dev, rtc_dd->alarm_irq, rtc_dd);
}

static struct platform_driver pm8xxx_rtc_driver = {
	.probe		= pm8xxx_rtc_probe,
	.remove_new	= pm8xxx_remove,
	.driver	= {
		.name		= "rtc-pm8xxx",
		.of_match_table	= pm8xxx_id_table,
	},
	.shutdown	= pm8xxx_rtc_shutdown,
};

module_platform_driver(pm8xxx_rtc_driver);

MODULE_ALIAS("platform:rtc-pm8xxx");
MODULE_DESCRIPTION("PMIC8xxx RTC driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Anirudh Ghayal <aghayal@codeaurora.org>");
MODULE_AUTHOR("Johan Hovold <johan@kernel.org>");
