// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-msm.h"

#define FUNCTION(fname)			                \
	[msm_mux_##fname] = {		                \
		.name = #fname,				\
		.groups = fname##_groups,               \
		.ngroups = ARRAY_SIZE(fname##_groups),	\
	}

#define REG_BASE 0x100000
#define REG_SIZE 0x1000
#define PINGROUP(id, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, wake_off, bit)	\
	{					        \
		.grp = PINCTRL_PINGROUP("gpio" #id,	\
			gpio##id##_pins,		\
			ARRAY_SIZE(gpio##id##_pins)),	\
		.ctl_reg = REG_BASE + REG_SIZE * id,			\
		.io_reg = REG_BASE + 0x4 + REG_SIZE * id,		\
		.intr_cfg_reg = REG_BASE + 0x8 + REG_SIZE * id,		\
		.intr_status_reg = REG_BASE + 0xc + REG_SIZE * id,	\
		.intr_target_reg = REG_BASE + 0x8 + REG_SIZE * id,	\
		.mux_bit = 2,			\
		.pull_bit = 0,			\
		.drv_bit = 6,			\
		.egpio_enable = 12,		\
		.egpio_present = 11,	\
		.oe_bit = 9,			\
		.in_bit = 0,			\
		.out_bit = 1,			\
		.intr_enable_bit = 0,		\
		.intr_status_bit = 0,		\
		.intr_target_bit = 5,		\
		.intr_target_kpss_val = 3,	\
		.intr_raw_status_bit = 4,	\
		.intr_polarity_bit = 1,		\
		.intr_detection_bit = 2,	\
		.intr_detection_width = 2,	\
		.wake_reg = REG_BASE + wake_off,	\
		.wake_bit = bit,		\
		.funcs = (int[]){			\
			msm_mux_gpio, /* gpio mode */	\
			msm_mux_##f1,			\
			msm_mux_##f2,			\
			msm_mux_##f3,			\
			msm_mux_##f4,			\
			msm_mux_##f5,			\
			msm_mux_##f6,			\
			msm_mux_##f7,			\
			msm_mux_##f8,			\
			msm_mux_##f9,			\
			msm_mux_##f10,			\
			msm_mux_##f11 /* egpio mode */	\
		},					        \
		.nfuncs = 12,				\
	}

#define SDC_QDSD_PINGROUP(pg_name, ctl, pull, drv)	\
	{					        \
		.grp = PINCTRL_PINGROUP(#pg_name,	\
			pg_name##_pins,			\
			ARRAY_SIZE(pg_name##_pins)),	\
		.ctl_reg = ctl,				\
		.io_reg = 0,				\
		.intr_cfg_reg = 0,			\
		.intr_status_reg = 0,			\
		.intr_target_reg = 0,			\
		.mux_bit = -1,				\
		.pull_bit = pull,			\
		.drv_bit = drv,				\
		.oe_bit = -1,				\
		.in_bit = -1,				\
		.out_bit = -1,				\
		.intr_enable_bit = -1,			\
		.intr_status_bit = -1,			\
		.intr_target_bit = -1,			\
		.intr_raw_status_bit = -1,		\
		.intr_polarity_bit = -1,		\
		.intr_detection_bit = -1,		\
		.intr_detection_width = -1,		\
	}

#define UFS_RESET(pg_name, offset, io)				\
	{					        \
		.grp = PINCTRL_PINGROUP(#pg_name,	\
			pg_name##_pins,			\
			ARRAY_SIZE(pg_name##_pins)),	\
		.ctl_reg = offset,			\
		.io_reg = io,				\
		.intr_cfg_reg = 0,			\
		.intr_status_reg = 0,			\
		.intr_target_reg = 0,			\
		.mux_bit = -1,				\
		.pull_bit = 3,				\
		.drv_bit = 0,				\
		.oe_bit = -1,				\
		.in_bit = -1,				\
		.out_bit = 0,				\
		.intr_enable_bit = -1,			\
		.intr_status_bit = -1,			\
		.intr_target_bit = -1,			\
		.intr_raw_status_bit = -1,		\
		.intr_polarity_bit = -1,		\
		.intr_detection_bit = -1,		\
		.intr_detection_width = -1,		\
	}

#define QUP_I3C(qup_mode, qup_offset)			\
	{						\
		.mode = qup_mode,			\
		.offset = REG_BASE + qup_offset,			\
	}

#define QUP_1_I3C_0_MODE_OFFSET	0xD4000
#define QUP_1_I3C_1_MODE_OFFSET	0xD5000
#define QUP_1_I3C_4_MODE_OFFSET	0xD6000
#define QUP_1_I3C_6_MODE_OFFSET	0xD7000
#define QUP_2_I3C_0_MODE_OFFSET	0xD8000
#define QUP_2_I3C_1_MODE_OFFSET	0xD9000
#define QUP_2_I3C_2_MODE_OFFSET	0xDA000
#define QUP_2_I3C_3_MODE_OFFSET	0xDB000
#define QUP_2_I3C_4_MODE_OFFSET	0xDC000
#define QUP_2_I3C_6_MODE_OFFSET	0xDD000

static const struct pinctrl_pin_desc kera_pins[] = {
	PINCTRL_PIN(0, "GPIO_0"),
	PINCTRL_PIN(1, "GPIO_1"),
	PINCTRL_PIN(2, "GPIO_2"),
	PINCTRL_PIN(3, "GPIO_3"),
	PINCTRL_PIN(4, "GPIO_4"),
	PINCTRL_PIN(5, "GPIO_5"),
	PINCTRL_PIN(6, "GPIO_6"),
	PINCTRL_PIN(7, "GPIO_7"),
	PINCTRL_PIN(8, "GPIO_8"),
	PINCTRL_PIN(9, "GPIO_9"),
	PINCTRL_PIN(10, "GPIO_10"),
	PINCTRL_PIN(11, "GPIO_11"),
	PINCTRL_PIN(12, "GPIO_12"),
	PINCTRL_PIN(13, "GPIO_13"),
	PINCTRL_PIN(14, "NA"),
	PINCTRL_PIN(15, "NA"),
	PINCTRL_PIN(16, "GPIO_16"),
	PINCTRL_PIN(17, "GPIO_17"),
	PINCTRL_PIN(18, "GPIO_18"),
	PINCTRL_PIN(19, "GPIO_19"),
	PINCTRL_PIN(20, "GPIO_20"),
	PINCTRL_PIN(21, "GPIO_21"),
	PINCTRL_PIN(22, "GPIO_22"),
	PINCTRL_PIN(23, "GPIO_23"),
	PINCTRL_PIN(24, "NA"),
	PINCTRL_PIN(25, "NA"),
	PINCTRL_PIN(26, "GPIO_26"),
	PINCTRL_PIN(27, "GPIO_27"),
	PINCTRL_PIN(28, "GPIO_28"),
	PINCTRL_PIN(29, "GPIO_29"),
	PINCTRL_PIN(30, "GPIO_30"),
	PINCTRL_PIN(31, "GPIO_31"),
	PINCTRL_PIN(32, "GPIO_32"),
	PINCTRL_PIN(33, "GPIO_33"),
	PINCTRL_PIN(34, "GPIO_34"),
	PINCTRL_PIN(35, "GPIO_35"),
	PINCTRL_PIN(36, "GPIO_36"),
	PINCTRL_PIN(37, "GPIO_37"),
	PINCTRL_PIN(38, "GPIO_38"),
	PINCTRL_PIN(39, "GPIO_39"),
	PINCTRL_PIN(40, "GPIO_40"),
	PINCTRL_PIN(41, "NA"),
	PINCTRL_PIN(42, "GPIO_42"),
	PINCTRL_PIN(43, "NA"),
	PINCTRL_PIN(44, "GPIO_44"),
	PINCTRL_PIN(45, "GPIO_45"),
	PINCTRL_PIN(46, "GPIO_46"),
	PINCTRL_PIN(47, "GPIO_47"),
	PINCTRL_PIN(48, "GPIO_48"),
	PINCTRL_PIN(49, "GPIO_49"),
	PINCTRL_PIN(50, "GPIO_50"),
	PINCTRL_PIN(51, "GPIO_51"),
	PINCTRL_PIN(52, "GPIO_52"),
	PINCTRL_PIN(53, "GPIO_53"),
	PINCTRL_PIN(54, "GPIO_54"),
	PINCTRL_PIN(55, "GPIO_55"),
	PINCTRL_PIN(56, "GPIO_56"),
	PINCTRL_PIN(57, "GPIO_57"),
	PINCTRL_PIN(58, "GPIO_58"),
	PINCTRL_PIN(59, "GPIO_59"),
	PINCTRL_PIN(60, "GPIO_60"),
	PINCTRL_PIN(61, "GPIO_61"),
	PINCTRL_PIN(62, "GPIO_62"),
	PINCTRL_PIN(63, "GPIO_63"),
	PINCTRL_PIN(64, "GPIO_64"),
	PINCTRL_PIN(65, "GPIO_65"),
	PINCTRL_PIN(66, "GPIO_66"),
	PINCTRL_PIN(67, "GPIO_67"),
	PINCTRL_PIN(68, "GPIO_68"),
	PINCTRL_PIN(69, "GPIO_69"),
	PINCTRL_PIN(70, "GPIO_70"),
	PINCTRL_PIN(71, "GPIO_71"),
	PINCTRL_PIN(72, "GPIO_72"),
	PINCTRL_PIN(73, "GPIO_73"),
	PINCTRL_PIN(74, "GPIO_74"),
	PINCTRL_PIN(75, "GPIO_75"),
	PINCTRL_PIN(76, "GPIO_76"),
	PINCTRL_PIN(77, "GPIO_77"),
	PINCTRL_PIN(78, "GPIO_78"),
	PINCTRL_PIN(79, "GPIO_79"),
	PINCTRL_PIN(80, "GPIO_80"),
	PINCTRL_PIN(81, "GPIO_81"),
	PINCTRL_PIN(82, "GPIO_82"),
	PINCTRL_PIN(83, "NA"),
	PINCTRL_PIN(84, "GPIO_84"),
	PINCTRL_PIN(85, "GPIO_85"),
	PINCTRL_PIN(86, "GPIO_86"),
	PINCTRL_PIN(87, "GPIO_87"),
	PINCTRL_PIN(88, "GPIO_88"),
	PINCTRL_PIN(89, "GPIO_89"),
	PINCTRL_PIN(90, "GPIO_90"),
	PINCTRL_PIN(91, "GPIO_91"),
	PINCTRL_PIN(92, "GPIO_92"),
	PINCTRL_PIN(93, "GPIO_93"),
	PINCTRL_PIN(94, "GPIO_94"),
	PINCTRL_PIN(95, "GPIO_95"),
	PINCTRL_PIN(96, "GPIO_96"),
	PINCTRL_PIN(97, "GPIO_97"),
	PINCTRL_PIN(98, "GPIO_98"),
	PINCTRL_PIN(99, "GPIO_99"),
	PINCTRL_PIN(100, "GPIO_100"),
	PINCTRL_PIN(101, "GPIO_101"),
	PINCTRL_PIN(102, "GPIO_102"),
	PINCTRL_PIN(103, "GPIO_103"),
	PINCTRL_PIN(104, "GPIO_104"),
	PINCTRL_PIN(105, "GPIO_105"),
	PINCTRL_PIN(106, "GPIO_106"),
	PINCTRL_PIN(107, "GPIO_107"),
	PINCTRL_PIN(108, "GPIO_108"),
	PINCTRL_PIN(109, "GPIO_109"),
	PINCTRL_PIN(110, "GPIO_110"),
	PINCTRL_PIN(111, "GPIO_111"),
	PINCTRL_PIN(112, "GPIO_112"),
	PINCTRL_PIN(113, "GPIO_113"),
	PINCTRL_PIN(114, "GPIO_114"),
	PINCTRL_PIN(115, "GPIO_115"),
	PINCTRL_PIN(116, "GPIO_116"),
	PINCTRL_PIN(117, "GPIO_117"),
	PINCTRL_PIN(118, "GPIO_118"),
	PINCTRL_PIN(119, "GPIO_119"),
	PINCTRL_PIN(120, "GPIO_120"),
	PINCTRL_PIN(121, "GPIO_121"),
	PINCTRL_PIN(122, "GPIO_122"),
	PINCTRL_PIN(123, "GPIO_123"),
	PINCTRL_PIN(124, "GPIO_124"),
	PINCTRL_PIN(125, "GPIO_125"),
	PINCTRL_PIN(126, "GPIO_126"),
	PINCTRL_PIN(127, "GPIO_127"),
	PINCTRL_PIN(128, "GPIO_128"),
	PINCTRL_PIN(129, "GPIO_129"),
	PINCTRL_PIN(130, "GPIO_130"),
	PINCTRL_PIN(131, "GPIO_131"),
	PINCTRL_PIN(132, "GPIO_132"),
	PINCTRL_PIN(133, "GPIO_133"),
	PINCTRL_PIN(134, "GPIO_134"),
	PINCTRL_PIN(135, "GPIO_135"),
	PINCTRL_PIN(136, "NA"),
	PINCTRL_PIN(137, "NA"),
	PINCTRL_PIN(138, "GPIO_138"),
	PINCTRL_PIN(139, "GPIO_139"),
	PINCTRL_PIN(140, "GPIO_140"),
	PINCTRL_PIN(141, "GPIO_141"),
	PINCTRL_PIN(142, "GPIO_142"),
	PINCTRL_PIN(143, "GPIO_143"),
	PINCTRL_PIN(144, "GPIO_144"),
	PINCTRL_PIN(145, "GPIO_145"),
	PINCTRL_PIN(146, "GPIO_146"),
	PINCTRL_PIN(147, "GPIO_147"),
	PINCTRL_PIN(148, "GPIO_148"),
	PINCTRL_PIN(149, "GPIO_149"),
	PINCTRL_PIN(150, "GPIO_150"),
	PINCTRL_PIN(151, "GPIO_151"),
	PINCTRL_PIN(152, "GPIO_152"),
	PINCTRL_PIN(153, "GPIO_153"),
	PINCTRL_PIN(154, "GPIO_154"),
	PINCTRL_PIN(155, "GPIO_155"),
	PINCTRL_PIN(156, "GPIO_156"),
	PINCTRL_PIN(157, "GPIO_157"),
	PINCTRL_PIN(158, "GPIO_158"),
	PINCTRL_PIN(159, "GPIO_159"),
	PINCTRL_PIN(160, "GPIO_160"),
	PINCTRL_PIN(161, "GPIO_161"),
	PINCTRL_PIN(162, "GPIO_162"),
	PINCTRL_PIN(163, "GPIO_163"),
	PINCTRL_PIN(164, "GPIO_164"),
	PINCTRL_PIN(165, "GPIO_165"),
	PINCTRL_PIN(166, "GPIO_166"),
	PINCTRL_PIN(167, "GPIO_167"),
	PINCTRL_PIN(168, "GPIO_168"),
	PINCTRL_PIN(169, "GPIO_169"),
	PINCTRL_PIN(170, "GPIO_170"),
	PINCTRL_PIN(171, "GPIO_171"),
	PINCTRL_PIN(172, "GPIO_172"),
	PINCTRL_PIN(173, "GPIO_173"),
	PINCTRL_PIN(174, "GPIO_174"),
	PINCTRL_PIN(175, "GPIO_175"),
	PINCTRL_PIN(176, "GPIO_176"),
	PINCTRL_PIN(177, "GPIO_177"),
	PINCTRL_PIN(178, "GPIO_178"),
	PINCTRL_PIN(179, "GPIO_179"),
	PINCTRL_PIN(180, "GPIO_180"),
	PINCTRL_PIN(181, "GPIO_181"),
	PINCTRL_PIN(182, "GPIO_182"),
	PINCTRL_PIN(183, "NA"),
	PINCTRL_PIN(184, "UFS_RESET"),
};

#define DECLARE_MSM_GPIO_PINS(pin) \
	static const unsigned int gpio##pin##_pins[] = { pin }
DECLARE_MSM_GPIO_PINS(0);
DECLARE_MSM_GPIO_PINS(1);
DECLARE_MSM_GPIO_PINS(2);
DECLARE_MSM_GPIO_PINS(3);
DECLARE_MSM_GPIO_PINS(4);
DECLARE_MSM_GPIO_PINS(5);
DECLARE_MSM_GPIO_PINS(6);
DECLARE_MSM_GPIO_PINS(7);
DECLARE_MSM_GPIO_PINS(8);
DECLARE_MSM_GPIO_PINS(9);
DECLARE_MSM_GPIO_PINS(10);
DECLARE_MSM_GPIO_PINS(11);
DECLARE_MSM_GPIO_PINS(12);
DECLARE_MSM_GPIO_PINS(13);
DECLARE_MSM_GPIO_PINS(14);
DECLARE_MSM_GPIO_PINS(15);
DECLARE_MSM_GPIO_PINS(16);
DECLARE_MSM_GPIO_PINS(17);
DECLARE_MSM_GPIO_PINS(18);
DECLARE_MSM_GPIO_PINS(19);
DECLARE_MSM_GPIO_PINS(20);
DECLARE_MSM_GPIO_PINS(21);
DECLARE_MSM_GPIO_PINS(22);
DECLARE_MSM_GPIO_PINS(23);
DECLARE_MSM_GPIO_PINS(24);
DECLARE_MSM_GPIO_PINS(25);
DECLARE_MSM_GPIO_PINS(26);
DECLARE_MSM_GPIO_PINS(27);
DECLARE_MSM_GPIO_PINS(28);
DECLARE_MSM_GPIO_PINS(29);
DECLARE_MSM_GPIO_PINS(30);
DECLARE_MSM_GPIO_PINS(31);
DECLARE_MSM_GPIO_PINS(32);
DECLARE_MSM_GPIO_PINS(33);
DECLARE_MSM_GPIO_PINS(34);
DECLARE_MSM_GPIO_PINS(35);
DECLARE_MSM_GPIO_PINS(36);
DECLARE_MSM_GPIO_PINS(37);
DECLARE_MSM_GPIO_PINS(38);
DECLARE_MSM_GPIO_PINS(39);
DECLARE_MSM_GPIO_PINS(40);
DECLARE_MSM_GPIO_PINS(41);
DECLARE_MSM_GPIO_PINS(42);
DECLARE_MSM_GPIO_PINS(43);
DECLARE_MSM_GPIO_PINS(44);
DECLARE_MSM_GPIO_PINS(45);
DECLARE_MSM_GPIO_PINS(46);
DECLARE_MSM_GPIO_PINS(47);
DECLARE_MSM_GPIO_PINS(48);
DECLARE_MSM_GPIO_PINS(49);
DECLARE_MSM_GPIO_PINS(50);
DECLARE_MSM_GPIO_PINS(51);
DECLARE_MSM_GPIO_PINS(52);
DECLARE_MSM_GPIO_PINS(53);
DECLARE_MSM_GPIO_PINS(54);
DECLARE_MSM_GPIO_PINS(55);
DECLARE_MSM_GPIO_PINS(56);
DECLARE_MSM_GPIO_PINS(57);
DECLARE_MSM_GPIO_PINS(58);
DECLARE_MSM_GPIO_PINS(59);
DECLARE_MSM_GPIO_PINS(60);
DECLARE_MSM_GPIO_PINS(61);
DECLARE_MSM_GPIO_PINS(62);
DECLARE_MSM_GPIO_PINS(63);
DECLARE_MSM_GPIO_PINS(64);
DECLARE_MSM_GPIO_PINS(65);
DECLARE_MSM_GPIO_PINS(66);
DECLARE_MSM_GPIO_PINS(67);
DECLARE_MSM_GPIO_PINS(68);
DECLARE_MSM_GPIO_PINS(69);
DECLARE_MSM_GPIO_PINS(70);
DECLARE_MSM_GPIO_PINS(71);
DECLARE_MSM_GPIO_PINS(72);
DECLARE_MSM_GPIO_PINS(73);
DECLARE_MSM_GPIO_PINS(74);
DECLARE_MSM_GPIO_PINS(75);
DECLARE_MSM_GPIO_PINS(76);
DECLARE_MSM_GPIO_PINS(77);
DECLARE_MSM_GPIO_PINS(78);
DECLARE_MSM_GPIO_PINS(79);
DECLARE_MSM_GPIO_PINS(80);
DECLARE_MSM_GPIO_PINS(81);
DECLARE_MSM_GPIO_PINS(82);
DECLARE_MSM_GPIO_PINS(83);
DECLARE_MSM_GPIO_PINS(84);
DECLARE_MSM_GPIO_PINS(85);
DECLARE_MSM_GPIO_PINS(86);
DECLARE_MSM_GPIO_PINS(87);
DECLARE_MSM_GPIO_PINS(88);
DECLARE_MSM_GPIO_PINS(89);
DECLARE_MSM_GPIO_PINS(90);
DECLARE_MSM_GPIO_PINS(91);
DECLARE_MSM_GPIO_PINS(92);
DECLARE_MSM_GPIO_PINS(93);
DECLARE_MSM_GPIO_PINS(94);
DECLARE_MSM_GPIO_PINS(95);
DECLARE_MSM_GPIO_PINS(96);
DECLARE_MSM_GPIO_PINS(97);
DECLARE_MSM_GPIO_PINS(98);
DECLARE_MSM_GPIO_PINS(99);
DECLARE_MSM_GPIO_PINS(100);
DECLARE_MSM_GPIO_PINS(101);
DECLARE_MSM_GPIO_PINS(102);
DECLARE_MSM_GPIO_PINS(103);
DECLARE_MSM_GPIO_PINS(104);
DECLARE_MSM_GPIO_PINS(105);
DECLARE_MSM_GPIO_PINS(106);
DECLARE_MSM_GPIO_PINS(107);
DECLARE_MSM_GPIO_PINS(108);
DECLARE_MSM_GPIO_PINS(109);
DECLARE_MSM_GPIO_PINS(110);
DECLARE_MSM_GPIO_PINS(111);
DECLARE_MSM_GPIO_PINS(112);
DECLARE_MSM_GPIO_PINS(113);
DECLARE_MSM_GPIO_PINS(114);
DECLARE_MSM_GPIO_PINS(115);
DECLARE_MSM_GPIO_PINS(116);
DECLARE_MSM_GPIO_PINS(117);
DECLARE_MSM_GPIO_PINS(118);
DECLARE_MSM_GPIO_PINS(119);
DECLARE_MSM_GPIO_PINS(120);
DECLARE_MSM_GPIO_PINS(121);
DECLARE_MSM_GPIO_PINS(122);
DECLARE_MSM_GPIO_PINS(123);
DECLARE_MSM_GPIO_PINS(124);
DECLARE_MSM_GPIO_PINS(125);
DECLARE_MSM_GPIO_PINS(126);
DECLARE_MSM_GPIO_PINS(127);
DECLARE_MSM_GPIO_PINS(128);
DECLARE_MSM_GPIO_PINS(129);
DECLARE_MSM_GPIO_PINS(130);
DECLARE_MSM_GPIO_PINS(131);
DECLARE_MSM_GPIO_PINS(132);
DECLARE_MSM_GPIO_PINS(133);
DECLARE_MSM_GPIO_PINS(134);
DECLARE_MSM_GPIO_PINS(135);
DECLARE_MSM_GPIO_PINS(136);
DECLARE_MSM_GPIO_PINS(137);
DECLARE_MSM_GPIO_PINS(138);
DECLARE_MSM_GPIO_PINS(139);
DECLARE_MSM_GPIO_PINS(140);
DECLARE_MSM_GPIO_PINS(141);
DECLARE_MSM_GPIO_PINS(142);
DECLARE_MSM_GPIO_PINS(143);
DECLARE_MSM_GPIO_PINS(144);
DECLARE_MSM_GPIO_PINS(145);
DECLARE_MSM_GPIO_PINS(146);
DECLARE_MSM_GPIO_PINS(147);
DECLARE_MSM_GPIO_PINS(148);
DECLARE_MSM_GPIO_PINS(149);
DECLARE_MSM_GPIO_PINS(150);
DECLARE_MSM_GPIO_PINS(151);
DECLARE_MSM_GPIO_PINS(152);
DECLARE_MSM_GPIO_PINS(153);
DECLARE_MSM_GPIO_PINS(154);
DECLARE_MSM_GPIO_PINS(155);
DECLARE_MSM_GPIO_PINS(156);
DECLARE_MSM_GPIO_PINS(157);
DECLARE_MSM_GPIO_PINS(158);
DECLARE_MSM_GPIO_PINS(159);
DECLARE_MSM_GPIO_PINS(160);
DECLARE_MSM_GPIO_PINS(161);
DECLARE_MSM_GPIO_PINS(162);
DECLARE_MSM_GPIO_PINS(163);
DECLARE_MSM_GPIO_PINS(164);
DECLARE_MSM_GPIO_PINS(165);
DECLARE_MSM_GPIO_PINS(166);
DECLARE_MSM_GPIO_PINS(167);
DECLARE_MSM_GPIO_PINS(168);
DECLARE_MSM_GPIO_PINS(169);
DECLARE_MSM_GPIO_PINS(170);
DECLARE_MSM_GPIO_PINS(171);
DECLARE_MSM_GPIO_PINS(172);
DECLARE_MSM_GPIO_PINS(173);
DECLARE_MSM_GPIO_PINS(174);
DECLARE_MSM_GPIO_PINS(175);
DECLARE_MSM_GPIO_PINS(176);
DECLARE_MSM_GPIO_PINS(177);
DECLARE_MSM_GPIO_PINS(178);
DECLARE_MSM_GPIO_PINS(179);
DECLARE_MSM_GPIO_PINS(180);
DECLARE_MSM_GPIO_PINS(181);
DECLARE_MSM_GPIO_PINS(182);
DECLARE_MSM_GPIO_PINS(183);

static const unsigned int ufs_reset_pins[] = { 184 };

enum kera_functions {
	msm_mux_gpio,
	msm_mux_SDC2_CLK,
	msm_mux_SDC2_CMD,
	msm_mux_SDC2_DATA0,
	msm_mux_SDC2_DATA1,
	msm_mux_SDC2_DATA2,
	msm_mux_SDC2_DATA3,
	msm_mux_aoss_cti,
	msm_mux_atest_char0,
	msm_mux_atest_char1,
	msm_mux_atest_char2,
	msm_mux_atest_char3,
	msm_mux_atest_char_start,
	msm_mux_atest_usb00,
	msm_mux_atest_usb01,
	msm_mux_audio_ext_mclk0,
	msm_mux_audio_ref_clk,
	msm_mux_cam_mclk,
	msm_mux_cci_async_in0,
	msm_mux_cci_async_in1,
	msm_mux_cci_async_in2,
	msm_mux_cci_i2c_scl0,
	msm_mux_cci_i2c_scl1,
	msm_mux_cci_i2c_scl2,
	msm_mux_cci_i2c_scl3,
	msm_mux_cci_i2c_sda0,
	msm_mux_cci_i2c_sda1,
	msm_mux_cci_i2c_sda2,
	msm_mux_cci_i2c_sda3,
	msm_mux_cci_timer0,
	msm_mux_cci_timer1,
	msm_mux_cci_timer2,
	msm_mux_cci_timer3,
	msm_mux_cci_timer4,
	msm_mux_coex_uart1_rx,
	msm_mux_coex_uart1_tx,
	msm_mux_coex_uart2_rx,
	msm_mux_coex_uart2_tx,
	msm_mux_dbg_out_clk,
	msm_mux_ddr_bist_complete,
	msm_mux_ddr_bist_fail,
	msm_mux_ddr_bist_start,
	msm_mux_ddr_bist_stop,
	msm_mux_ddr_pxi0,
	msm_mux_ddr_pxi1,
	msm_mux_dp0_hot,
	msm_mux_gcc_gp1,
	msm_mux_gcc_gp2,
	msm_mux_gcc_gp3,
	msm_mux_gnss_adc0,
	msm_mux_gnss_adc1,
	msm_mux_hdmi_ddc_scl,
	msm_mux_hdmi_ddc_sda,
	msm_mux_hdmi_dtest0,
	msm_mux_hdmi_dtest1,
	msm_mux_hdmi_hot_plug,
	msm_mux_hdmi_pixel_clk,
	msm_mux_hdmi_rcv_det,
	msm_mux_hdmi_tx_cec,
	msm_mux_host2wlan_sol,
	msm_mux_i2s0_data0,
	msm_mux_i2s0_data1,
	msm_mux_i2s0_sck,
	msm_mux_i2s0_ws,
	msm_mux_ibi_i3c,
	msm_mux_jitter_bist,
	msm_mux_mdp_esync0_out,
	msm_mux_mdp_esync1_out,
	msm_mux_mdp_vsync,
	msm_mux_mdp_vsync0_out,
	msm_mux_mdp_vsync11_out,
	msm_mux_mdp_vsync1_out,
	msm_mux_mdp_vsync2_out,
	msm_mux_mdp_vsync3_out,
	msm_mux_mdp_vsync_e,
	msm_mux_nav_gpio0,
	msm_mux_nav_gpio1,
	msm_mux_nav_gpio2,
	msm_mux_nav_gpio3,
	msm_mux_pcie0_clk_req_n,
	msm_mux_pcie1_clk_req_n,
	msm_mux_phase_flag0,
	msm_mux_phase_flag1,
	msm_mux_phase_flag10,
	msm_mux_phase_flag11,
	msm_mux_phase_flag12,
	msm_mux_phase_flag13,
	msm_mux_phase_flag14,
	msm_mux_phase_flag15,
	msm_mux_phase_flag16,
	msm_mux_phase_flag17,
	msm_mux_phase_flag18,
	msm_mux_phase_flag19,
	msm_mux_phase_flag2,
	msm_mux_phase_flag20,
	msm_mux_phase_flag21,
	msm_mux_phase_flag22,
	msm_mux_phase_flag23,
	msm_mux_phase_flag24,
	msm_mux_phase_flag25,
	msm_mux_phase_flag26,
	msm_mux_phase_flag27,
	msm_mux_phase_flag28,
	msm_mux_phase_flag29,
	msm_mux_phase_flag3,
	msm_mux_phase_flag30,
	msm_mux_phase_flag31,
	msm_mux_phase_flag4,
	msm_mux_phase_flag5,
	msm_mux_phase_flag6,
	msm_mux_phase_flag7,
	msm_mux_phase_flag8,
	msm_mux_phase_flag9,
	msm_mux_pll_bist_sync,
	msm_mux_pll_clk_aux,
	msm_mux_prng_rosc0,
	msm_mux_prng_rosc1,
	msm_mux_prng_rosc2,
	msm_mux_prng_rosc3,
	msm_mux_qdss_cti,
	msm_mux_qdss_gpio,
	msm_mux_qdss_gpio0,
	msm_mux_qdss_gpio1,
	msm_mux_qdss_gpio10,
	msm_mux_qdss_gpio11,
	msm_mux_qdss_gpio12,
	msm_mux_qdss_gpio13,
	msm_mux_qdss_gpio14,
	msm_mux_qdss_gpio15,
	msm_mux_qdss_gpio2,
	msm_mux_qdss_gpio3,
	msm_mux_qdss_gpio4,
	msm_mux_qdss_gpio5,
	msm_mux_qdss_gpio6,
	msm_mux_qdss_gpio7,
	msm_mux_qdss_gpio8,
	msm_mux_qdss_gpio9,
	msm_mux_qlink_big_enable,
	msm_mux_qlink_big_request,
	msm_mux_qlink_little_enable,
	msm_mux_qlink_little_request,
	msm_mux_qlink_wmss,
	msm_mux_qspi0_clk,
	msm_mux_qspi0_cs0_n,
	msm_mux_qspi0_cs1_n,
	msm_mux_qspi0_data0,
	msm_mux_qspi0_data1,
	msm_mux_qspi0_data2,
	msm_mux_qspi0_data3,
	msm_mux_qup1_se0_l0,
	msm_mux_qup1_se0_l1,
	msm_mux_qup1_se0_l2,
	msm_mux_qup1_se0_l3,
	msm_mux_qup1_se1_l0,
	msm_mux_qup1_se1_l1,
	msm_mux_qup1_se1_l2,
	msm_mux_qup1_se1_l3,
	msm_mux_qup1_se2_l0,
	msm_mux_qup1_se2_l1,
	msm_mux_qup1_se2_l2_mira,
	msm_mux_qup1_se2_l2_mirb,
	msm_mux_qup1_se2_l3_mira,
	msm_mux_qup1_se2_l3_mirb,
	msm_mux_qup1_se2_l4,
	msm_mux_qup1_se2_l5,
	msm_mux_qup1_se2_l6,
	msm_mux_qup1_se3_l0,
	msm_mux_qup1_se3_l1,
	msm_mux_qup1_se3_l2,
	msm_mux_qup1_se3_l3,
	msm_mux_qup1_se4_l0,
	msm_mux_qup1_se4_l1,
	msm_mux_qup1_se4_l2,
	msm_mux_qup1_se4_l3,
	msm_mux_qup1_se5_l0,
	msm_mux_qup1_se5_l1,
	msm_mux_qup1_se5_l2,
	msm_mux_qup1_se5_l3,
	msm_mux_qup1_se5_l4,
	msm_mux_qup1_se5_l5,
	msm_mux_qup1_se6_l0,
	msm_mux_qup1_se6_l1_mira,
	msm_mux_qup1_se6_l1_mirb,
	msm_mux_qup1_se6_l2,
	msm_mux_qup1_se6_l3_mira,
	msm_mux_qup1_se6_l3_mirb,
	msm_mux_qup1_se7_l0_mira,
	msm_mux_qup1_se7_l0_mirb,
	msm_mux_qup1_se7_l1_mira,
	msm_mux_qup1_se7_l1_mirb,
	msm_mux_qup1_se7_l2,
	msm_mux_qup1_se7_l3,
	msm_mux_qup2_se0_l0,
	msm_mux_qup2_se0_l1,
	msm_mux_qup2_se0_l2,
	msm_mux_qup2_se0_l3,
	msm_mux_qup2_se1_l0,
	msm_mux_qup2_se1_l1,
	msm_mux_qup2_se1_l2,
	msm_mux_qup2_se1_l3,
	msm_mux_qup2_se2_l0,
	msm_mux_qup2_se2_l1,
	msm_mux_qup2_se2_l2,
	msm_mux_qup2_se2_l3,
	msm_mux_qup2_se2_l4,
	msm_mux_qup2_se2_l5,
	msm_mux_qup2_se2_l6,
	msm_mux_qup2_se3_l0_mira,
	msm_mux_qup2_se3_l0_mirb,
	msm_mux_qup2_se3_l1_mira,
	msm_mux_qup2_se3_l1_mirb,
	msm_mux_qup2_se3_l2,
	msm_mux_qup2_se3_l3,
	msm_mux_qup2_se4_l0,
	msm_mux_qup2_se4_l1,
	msm_mux_qup2_se4_l2,
	msm_mux_qup2_se4_l3,
	msm_mux_qup2_se5_l0,
	msm_mux_qup2_se5_l1,
	msm_mux_qup2_se5_l2,
	msm_mux_qup2_se5_l3,
	msm_mux_qup2_se6_l0,
	msm_mux_qup2_se6_l1,
	msm_mux_qup2_se6_l2,
	msm_mux_qup2_se6_l3,
	msm_mux_qup2_se7_l0,
	msm_mux_qup2_se7_l1,
	msm_mux_qup2_se7_l2,
	msm_mux_qup2_se7_l3,
	msm_mux_resout_gpio,
	msm_mux_sd_write_protect,
	msm_mux_sdc1None,
	msm_mux_sdc1_clk,
	msm_mux_sdc1_cmd,
	msm_mux_sdc1_rclk,
	msm_mux_sdc2_fb_clk,
	msm_mux_tb_trig_sdc1,
	msm_mux_tb_trig_sdc2,
	msm_mux_tmess_prng0,
	msm_mux_tmess_prng1,
	msm_mux_tmess_prng2,
	msm_mux_tmess_prng3,
	msm_mux_tsense_pwm1,
	msm_mux_tsense_pwm2,
	msm_mux_tsense_pwm3,
	msm_mux_tsense_pwm4,
	msm_mux_uim0_clk,
	msm_mux_uim0_data,
	msm_mux_uim0_present,
	msm_mux_uim0_reset,
	msm_mux_uim1_clk_mira,
	msm_mux_uim1_clk_mirb,
	msm_mux_uim1_data_mira,
	msm_mux_uim1_data_mirb,
	msm_mux_uim1_present_mira,
	msm_mux_uim1_present_mirb,
	msm_mux_uim1_reset_mira,
	msm_mux_uim1_reset_mirb,
	msm_mux_usb0_hs,
	msm_mux_usb0_phy_ps,
	msm_mux_vfr_0,
	msm_mux_vfr_1,
	msm_mux_vsense_trigger_mirnat,
	msm_mux_wcn_sw_ctrl,
	msm_mux_NA,
};

static const char *const gpio_groups[] = {
	"gpio0", "gpio1", "gpio2", "gpio3", "gpio4", "gpio5",
	"gpio6", "gpio7", "gpio8", "gpio9", "gpio10", "gpio11",
	"gpio12", "gpio13", "gpio16", "gpio17", "gpio18", "gpio19",
	"gpio20", "gpio21", "gpio22", "gpio23", "gpio26", "gpio27",
	"gpio28", "gpio29", "gpio30", "gpio31", "gpio32", "gpio33",
	"gpio34", "gpio35", "gpio36", "gpio37", "gpio38", "gpio39",
	"gpio40", "gpio42", "gpio44", "gpio45", "gpio46", "gpio47",
	"gpio48", "gpio49", "gpio50", "gpio51", "gpio52", "gpio53",
	"gpio54", "gpio55", "gpio56", "gpio57", "gpio58", "gpio59",
	"gpio60", "gpio61", "gpio62", "gpio63", "gpio64", "gpio65",
	"gpio66", "gpio67", "gpio68", "gpio69", "gpio70", "gpio71",
	"gpio72", "gpio73", "gpio74", "gpio75", "gpio76", "gpio77",
	"gpio78", "gpio79", "gpio80", "gpio81", "gpio82", "gpio84",
	"gpio85", "gpio86", "gpio87", "gpio88", "gpio89", "gpio90",
	"gpio91", "gpio92", "gpio93", "gpio94", "gpio95", "gpio96",
	"gpio97", "gpio98", "gpio99", "gpio100", "gpio101", "gpio102",
	"gpio103", "gpio104", "gpio105", "gpio106", "gpio107", "gpio108",
	"gpio109", "gpio110", "gpio111", "gpio112", "gpio113", "gpio114",
	"gpio115", "gpio116", "gpio117", "gpio118", "gpio119", "gpio120",
	"gpio121", "gpio122", "gpio123", "gpio124", "gpio125", "gpio126",
	"gpio127", "gpio128", "gpio129", "gpio130", "gpio131", "gpio132",
	"gpio133", "gpio134", "gpio135", "gpio138", "gpio139", "gpio140",
	"gpio141", "gpio142", "gpio143", "gpio144", "gpio145", "gpio146",
	"gpio147", "gpio148", "gpio149", "gpio150", "gpio151", "gpio152",
	"gpio153", "gpio154", "gpio155", "gpio156", "gpio157", "gpio158",
	"gpio159", "gpio160", "gpio161", "gpio162", "gpio163", "gpio164",
	"gpio165", "gpio166", "gpio167", "gpio168", "gpio169", "gpio170",
	"gpio171", "gpio172", "gpio173", "gpio174", "gpio175", "gpio176",
	"gpio177", "gpio178", "gpio179", "gpio180", "gpio181", "gpio182",
	"gpio184",
};
static const char *const SDC2_CLK_groups[] = {
	"gpio62",
};
static const char *const SDC2_CMD_groups[] = {
	"gpio51",
};
static const char *const SDC2_DATA0_groups[] = {
	"gpio38",
};
static const char *const SDC2_DATA1_groups[] = {
	"gpio39",
};
static const char *const SDC2_DATA2_groups[] = {
	"gpio48",
};
static const char *const SDC2_DATA3_groups[] = {
	"gpio49",
};
static const char *const aoss_cti_groups[] = {
	"gpio0", "gpio1", "gpio26", "gpio27",
};
static const char *const atest_char0_groups[] = {
	"gpio71",
};
static const char *const atest_char1_groups[] = {
	"gpio70",
};
static const char *const atest_char2_groups[] = {
	"gpio72",
};
static const char *const atest_char3_groups[] = {
	"gpio74",
};
static const char *const atest_char_start_groups[] = {
	"gpio73",
};
static const char *const atest_usb00_groups[] = {
	"gpio55",
};
static const char *const atest_usb01_groups[] = {
	"gpio54",
};
static const char *const audio_ext_mclk0_groups[] = {
	"gpio69",
};
static const char *const audio_ref_clk_groups[] = {
	"gpio32",
};
static const char *const cam_mclk_groups[] = {
	"gpio65", "gpio66", "gpio67", "gpio68", "gpio69",
};
static const char *const cci_async_in0_groups[] = {
	"gpio115",
};
static const char *const cci_async_in1_groups[] = {
	"gpio31",
};
static const char *const cci_async_in2_groups[] = {
	"gpio30",
};
static const char *const cci_i2c_scl0_groups[] = {
	"gpio71",
};
static const char *const cci_i2c_scl1_groups[] = {
	"gpio73",
};
static const char *const cci_i2c_scl2_groups[] = {
	"gpio75",
};
static const char *const cci_i2c_scl3_groups[] = {
	"gpio77",
};
static const char *const cci_i2c_sda0_groups[] = {
	"gpio70",
};
static const char *const cci_i2c_sda1_groups[] = {
	"gpio72",
};
static const char *const cci_i2c_sda2_groups[] = {
	"gpio74",
};
static const char *const cci_i2c_sda3_groups[] = {
	"gpio76",
};
static const char *const cci_timer0_groups[] = {
	"gpio76",
};
static const char *const cci_timer1_groups[] = {
	"gpio63",
};
static const char *const cci_timer2_groups[] = {
	"gpio125",
};
static const char *const cci_timer3_groups[] = {
	"gpio126",
};
static const char *const cci_timer4_groups[] = {
	"gpio127",
};
static const char *const coex_uart1_rx_groups[] = {
	"gpio112",
};
static const char *const coex_uart1_tx_groups[] = {
	"gpio111",
};
static const char *const coex_uart2_rx_groups[] = {
	"gpio116",
};
static const char *const coex_uart2_tx_groups[] = {
	"gpio100",
};
static const char *const dbg_out_clk_groups[] = {
	"gpio81",
};
static const char *const ddr_bist_complete_groups[] = {
	"gpio52",
};
static const char *const ddr_bist_fail_groups[] = {
	"gpio147",
};
static const char *const ddr_bist_start_groups[] = {
	"gpio34",
};
static const char *const ddr_bist_stop_groups[] = {
	"gpio53",
};
static const char *const ddr_pxi0_groups[] = {
	"gpio54", "gpio55",
};
static const char *const ddr_pxi1_groups[] = {
	"gpio40", "gpio42",
};
static const char *const dp0_hot_groups[] = {
	"gpio55",
};
static const char *const gcc_gp1_groups[] = {
	"gpio27", "gpio53",
};
static const char *const gcc_gp2_groups[] = {
	"gpio32", "gpio35",
};
static const char *const gcc_gp3_groups[] = {
	"gpio30", "gpio33",
};
static const char *const gnss_adc0_groups[] = {
	"gpio42", "gpio55",
};
static const char *const gnss_adc1_groups[] = {
	"gpio40", "gpio54",
};
static const char *const hdmi_ddc_scl_groups[] = {
	"gpio6",
};
static const char *const hdmi_ddc_sda_groups[] = {
	"gpio7",
};
static const char *const hdmi_dtest0_groups[] = {
	"gpio132",
};
static const char *const hdmi_dtest1_groups[] = {
	"gpio133",
};
static const char *const hdmi_hot_plug_groups[] = {
	"gpio47",
};
static const char *const hdmi_pixel_clk_groups[] = {
	"gpio18",
};
static const char *const hdmi_rcv_det_groups[] = {
	"gpio19",
};
static const char *const hdmi_tx_cec_groups[] = {
	"gpio46",
};
static const char *const host2wlan_sol_groups[] = {
	"gpio33",
};
static const char *const i2s0_data0_groups[] = {
	"gpio64",
};
static const char *const i2s0_data1_groups[] = {
	"gpio63",
};
static const char *const i2s0_sck_groups[] = {
	"gpio60",
};
static const char *const i2s0_ws_groups[] = {
	"gpio61",
};
static const char *const ibi_i3c_groups[] = {
	"gpio0", "gpio1", "gpio4", "gpio5", "gpio12", "gpio13",
	"gpio28", "gpio29", "gpio32", "gpio33", "gpio36", "gpio37",
};
static const char *const jitter_bist_groups[] = {
	"gpio77",
};
static const char *const mdp_esync0_out_groups[] = {
	"gpio13",
};
static const char *const mdp_esync1_out_groups[] = {
	"gpio12",
};
static const char *const mdp_vsync_groups[] = {
	"gpio16", "gpio17", "gpio79", "gpio100", "gpio120", "gpio121",
};
static const char *const mdp_vsync0_out_groups[] = {
	"gpio17",
};
static const char *const mdp_vsync11_out_groups[] = {
	"gpio27",
};
static const char *const mdp_vsync1_out_groups[] = {
	"gpio17",
};
static const char *const mdp_vsync2_out_groups[] = {
	"gpio16",
};
static const char *const mdp_vsync3_out_groups[] = {
	"gpio16",
};
static const char *const mdp_vsync_e_groups[] = {
	"gpio13",
};
static const char *const nav_gpio0_groups[] = {
	"gpio119",
};
static const char *const nav_gpio1_groups[] = {
	"gpio117",
};
static const char *const nav_gpio2_groups[] = {
	"gpio118",
};
static const char *const nav_gpio3_groups[] = {
	"gpio113",
};
static const char *const pcie0_clk_req_n_groups[] = {
	"gpio80",
};
static const char *const pcie1_clk_req_n_groups[] = {
	"gpio52",
};
static const char *const phase_flag0_groups[] = {
	"gpio71",
};
static const char *const phase_flag1_groups[] = {
	"gpio70",
};
static const char *const phase_flag10_groups[] = {
	"gpio174",
};
static const char *const phase_flag11_groups[] = {
	"gpio175",
};
static const char *const phase_flag12_groups[] = {
	"gpio172",
};
static const char *const phase_flag13_groups[] = {
	"gpio171",
};
static const char *const phase_flag14_groups[] = {
	"gpio170",
};
static const char *const phase_flag15_groups[] = {
	"gpio169",
};
static const char *const phase_flag16_groups[] = {
	"gpio168",
};
static const char *const phase_flag17_groups[] = {
	"gpio167",
};
static const char *const phase_flag18_groups[] = {
	"gpio166",
};
static const char *const phase_flag19_groups[] = {
	"gpio165",
};
static const char *const phase_flag2_groups[] = {
	"gpio182",
};
static const char *const phase_flag20_groups[] = {
	"gpio164",
};
static const char *const phase_flag21_groups[] = {
	"gpio163",
};
static const char *const phase_flag22_groups[] = {
	"gpio162",
};
static const char *const phase_flag23_groups[] = {
	"gpio161",
};
static const char *const phase_flag24_groups[] = {
	"gpio160",
};
static const char *const phase_flag25_groups[] = {
	"gpio159",
};
static const char *const phase_flag26_groups[] = {
	"gpio158",
};
static const char *const phase_flag27_groups[] = {
	"gpio157",
};
static const char *const phase_flag28_groups[] = {
	"gpio80",
};
static const char *const phase_flag29_groups[] = {
	"gpio78",
};
static const char *const phase_flag3_groups[] = {
	"gpio181",
};
static const char *const phase_flag30_groups[] = {
	"gpio76",
};
static const char *const phase_flag31_groups[] = {
	"gpio75",
};
static const char *const phase_flag4_groups[] = {
	"gpio180",
};
static const char *const phase_flag5_groups[] = {
	"gpio179",
};
static const char *const phase_flag6_groups[] = {
	"gpio178",
};
static const char *const phase_flag7_groups[] = {
	"gpio177",
};
static const char *const phase_flag8_groups[] = {
	"gpio176",
};
static const char *const phase_flag9_groups[] = {
	"gpio173",
};
static const char *const pll_bist_sync_groups[] = {
	"gpio184",
};
static const char *const pll_clk_aux_groups[] = {
	"gpio135",
};
static const char *const prng_rosc0_groups[] = {
	"gpio67",
};
static const char *const prng_rosc1_groups[] = {
	"gpio69",
};
static const char *const prng_rosc2_groups[] = {
	"gpio76",
};
static const char *const prng_rosc3_groups[] = {
	"gpio74",
};
static const char *const qdss_cti_groups[] = {
	"gpio18", "gpio19", "gpio32", "gpio73", "gpio74", "gpio154",
	"gpio176", "gpio184",
};
static const char *const qdss_gpio_groups[] = {
	"gpio54", "gpio72", "gpio144", "gpio147",
};
static const char *const qdss_gpio0_groups[] = {
	"gpio30", "gpio163",
};
static const char *const qdss_gpio1_groups[] = {
	"gpio31", "gpio164",
};
static const char *const qdss_gpio10_groups[] = {
	"gpio67", "gpio179",
};
static const char *const qdss_gpio11_groups[] = {
	"gpio53", "gpio180",
};
static const char *const qdss_gpio12_groups[] = {
	"gpio52", "gpio181",
};
static const char *const qdss_gpio13_groups[] = {
	"gpio65", "gpio182",
};
static const char *const qdss_gpio14_groups[] = {
	"gpio66", "gpio177",
};
static const char *const qdss_gpio15_groups[] = {
	"gpio114", "gpio155",
};
static const char *const qdss_gpio2_groups[] = {
	"gpio34", "gpio167",
};
static const char *const qdss_gpio3_groups[] = {
	"gpio35", "gpio168",
};
static const char *const qdss_gpio4_groups[] = {
	"gpio135", "gpio169",
};
static const char *const qdss_gpio5_groups[] = {
	"gpio134", "gpio170",
};
static const char *const qdss_gpio6_groups[] = {
	"gpio42", "gpio156",
};
static const char *const qdss_gpio7_groups[] = {
	"gpio40", "gpio146",
};
static const char *const qdss_gpio8_groups[] = {
	"gpio132", "gpio178",
};
static const char *const qdss_gpio9_groups[] = {
	"gpio133", "gpio145",
};
static const char *const qlink_big_enable_groups[] = {
	"gpio96",
};
static const char *const qlink_big_request_groups[] = {
	"gpio95",
};
static const char *const qlink_little_enable_groups[] = {
	"gpio93",
};
static const char *const qlink_little_request_groups[] = {
	"gpio92",
};
static const char *const qlink_wmss_groups[] = {
	"gpio94",
};
static const char *const qspi0_clk_groups[] = {
	"gpio79",
};
static const char *const qspi0_cs0_n_groups[] = {
	"gpio116",
};
static const char *const qspi0_cs1_n_groups[] = {
	"gpio115",
};
static const char *const qspi0_data0_groups[] = {
	"gpio97",
};
static const char *const qspi0_data1_groups[] = {
	"gpio98",
};
static const char *const qspi0_data2_groups[] = {
	"gpio99",
};
static const char *const qspi0_data3_groups[] = {
	"gpio100",
};
static const char *const qup1_se0_l0_groups[] = {
	"gpio28",
};
static const char *const qup1_se0_l1_groups[] = {
	"gpio29",
};
static const char *const qup1_se0_l2_groups[] = {
	"gpio30",
};
static const char *const qup1_se0_l3_groups[] = {
	"gpio31",
};
static const char *const qup1_se1_l0_groups[] = {
	"gpio32",
};
static const char *const qup1_se1_l1_groups[] = {
	"gpio33",
};
static const char *const qup1_se1_l2_groups[] = {
	"gpio34",
};
static const char *const qup1_se1_l3_groups[] = {
	"gpio35",
};
static const char *const qup1_se2_l0_groups[] = {
	"gpio52",
};
static const char *const qup1_se2_l1_groups[] = {
	"gpio53",
};
static const char *const qup1_se2_l2_mira_groups[] = {
	"gpio54",
};
static const char *const qup1_se2_l2_mirb_groups[] = {
	"gpio52",
};
static const char *const qup1_se2_l3_mira_groups[] = {
	"gpio55",
};
static const char *const qup1_se2_l3_mirb_groups[] = {
	"gpio53",
};
static const char *const qup1_se2_l4_groups[] = {
	"gpio40",
};
static const char *const qup1_se2_l5_groups[] = {
	"gpio42",
};
static const char *const qup1_se2_l6_groups[] = {
	"gpio30",
};
static const char *const qup1_se3_l0_groups[] = {
	"gpio44",
};
static const char *const qup1_se3_l1_groups[] = {
	"gpio45",
};
static const char *const qup1_se3_l2_groups[] = {
	"gpio46",
};
static const char *const qup1_se3_l3_groups[] = {
	"gpio47",
};
static const char *const qup1_se4_l0_groups[] = {
	"gpio36",
};
static const char *const qup1_se4_l1_groups[] = {
	"gpio37",
};
static const char *const qup1_se4_l2_groups[] = {
	"gpio37",
};
static const char *const qup1_se4_l3_groups[] = {
	"gpio36",
};
static const char *const qup1_se5_l0_groups[] = {
	"gpio132",
};
static const char *const qup1_se5_l1_groups[] = {
	"gpio133",
};
static const char *const qup1_se5_l2_groups[] = {
	"gpio134",
};
static const char *const qup1_se5_l3_groups[] = {
	"gpio135",
};
static const char *const qup1_se5_l4_groups[] = {
	"gpio34",
};
static const char *const qup1_se5_l5_groups[] = {
	"gpio35",
};
static const char *const qup1_se6_l0_groups[] = {
	"gpio40",
};
static const char *const qup1_se6_l1_mira_groups[] = {
	"gpio42",
};
static const char *const qup1_se6_l1_mirb_groups[] = {
	"gpio54",
};
static const char *const qup1_se6_l2_groups[] = {
	"gpio42",
};
static const char *const qup1_se6_l3_mira_groups[] = {
	"gpio40",
};
static const char *const qup1_se6_l3_mirb_groups[] = {
	"gpio55",
};
static const char *const qup1_se7_l0_mira_groups[] = {
	"gpio81",
};
static const char *const qup1_se7_l0_mirb_groups[] = {
	"gpio78",
};
static const char *const qup1_se7_l1_mira_groups[] = {
	"gpio80",
};
static const char *const qup1_se7_l1_mirb_groups[] = {
	"gpio114",
};
static const char *const qup1_se7_l2_groups[] = {
	"gpio114",
};
static const char *const qup1_se7_l3_groups[] = {
	"gpio78",
};
static const char *const qup2_se0_l0_groups[] = {
	"gpio0",
};
static const char *const qup2_se0_l1_groups[] = {
	"gpio1",
};
static const char *const qup2_se0_l2_groups[] = {
	"gpio2",
};
static const char *const qup2_se0_l3_groups[] = {
	"gpio3",
};
static const char *const qup2_se1_l0_groups[] = {
	"gpio4",
};
static const char *const qup2_se1_l1_groups[] = {
	"gpio5",
};
static const char *const qup2_se1_l2_groups[] = {
	"gpio6",
};
static const char *const qup2_se1_l3_groups[] = {
	"gpio7",
};
static const char *const qup2_se2_l0_groups[] = {
	"gpio8",
};
static const char *const qup2_se2_l1_groups[] = {
	"gpio9",
};
static const char *const qup2_se2_l2_groups[] = {
	"gpio10",
};
static const char *const qup2_se2_l3_groups[] = {
	"gpio11",
};
static const char *const qup2_se2_l4_groups[] = {
	"gpio16",
};
static const char *const qup2_se2_l5_groups[] = {
	"gpio17",
};
static const char *const qup2_se2_l6_groups[] = {
	"gpio18",
};
static const char *const qup2_se3_l0_mira_groups[] = {
	"gpio79",
};
static const char *const qup2_se3_l0_mirb_groups[] = {
	"gpio116",
};
static const char *const qup2_se3_l1_mira_groups[] = {
	"gpio97",
};
static const char *const qup2_se3_l1_mirb_groups[] = {
	"gpio100",
};
static const char *const qup2_se3_l2_groups[] = {
	"gpio100",
};
static const char *const qup2_se3_l3_groups[] = {
	"gpio116",
};
static const char *const qup2_se4_l0_groups[] = {
	"gpio12",
};
static const char *const qup2_se4_l1_groups[] = {
	"gpio13",
};
static const char *const qup2_se4_l2_groups[] = {
	"gpio26",
};
static const char *const qup2_se4_l3_groups[] = {
	"gpio27",
};
static const char *const qup2_se5_l0_groups[] = {
	"gpio16",
};
static const char *const qup2_se5_l1_groups[] = {
	"gpio17",
};
static const char *const qup2_se5_l2_groups[] = {
	"gpio18",
};
static const char *const qup2_se5_l3_groups[] = {
	"gpio19",
};
static const char *const qup2_se6_l0_groups[] = {
	"gpio20",
};
static const char *const qup2_se6_l1_groups[] = {
	"gpio21",
};
static const char *const qup2_se6_l2_groups[] = {
	"gpio22",
};
static const char *const qup2_se6_l3_groups[] = {
	"gpio23",
};
static const char *const qup2_se7_l0_groups[] = {
	"gpio27",
};
static const char *const qup2_se7_l1_groups[] = {
	"gpio26",
};
static const char *const qup2_se7_l2_groups[] = {
	"gpio13",
};
static const char *const qup2_se7_l3_groups[] = {
	"gpio12",
};
static const char *const resout_gpio_groups[] = {
	"gpio63", "gpio69", "gpio175",
};
static const char *const sd_write_protect_groups[] = {
	"gpio57",
};
static const char *const sdc1None_groups[] = {
	"gpio124", "gpio125", "gpio126", "gpio127", "gpio128", "gpio129",
	"gpio130", "gpio131",
};
static const char *const sdc1_clk_groups[] = {
	"gpio121",
};
static const char *const sdc1_cmd_groups[] = {
	"gpio123",
};
static const char *const sdc1_rclk_groups[] = {
	"gpio120",
};
static const char *const sdc2_fb_clk_groups[] = {
	"gpio50",
};
static const char *const tb_trig_sdc1_groups[] = {
	"gpio34",
};
static const char *const tb_trig_sdc2_groups[] = {
	"gpio35",
};
static const char *const tmess_prng0_groups[] = {
	"gpio73",
};
static const char *const tmess_prng1_groups[] = {
	"gpio72",
};
static const char *const tmess_prng2_groups[] = {
	"gpio70",
};
static const char *const tmess_prng3_groups[] = {
	"gpio71",
};
static const char *const tsense_pwm1_groups[] = {
	"gpio56",
};
static const char *const tsense_pwm2_groups[] = {
	"gpio56",
};
static const char *const tsense_pwm3_groups[] = {
	"gpio56",
};
static const char *const tsense_pwm4_groups[] = {
	"gpio56",
};
static const char *const uim0_clk_groups[] = {
	"gpio85",
};
static const char *const uim0_data_groups[] = {
	"gpio84",
};
static const char *const uim0_present_groups[] = {
	"gpio87",
};
static const char *const uim0_reset_groups[] = {
	"gpio86",
};
static const char *const uim1_clk_mira_groups[] = {
	"gpio98",
};
static const char *const uim1_clk_mirb_groups[] = {
	"gpio89",
};
static const char *const uim1_data_mira_groups[] = {
	"gpio97",
};
static const char *const uim1_data_mirb_groups[] = {
	"gpio88",
};
static const char *const uim1_present_mira_groups[] = {
	"gpio100",
};
static const char *const uim1_present_mirb_groups[] = {
	"gpio91",
};
static const char *const uim1_reset_mira_groups[] = {
	"gpio99",
};
static const char *const uim1_reset_mirb_groups[] = {
	"gpio90",
};
static const char *const usb0_hs_groups[] = {
	"gpio56",
};
static const char *const usb0_phy_ps_groups[] = {
	"gpio122",
};
static const char *const vfr_0_groups[] = {
	"gpio63",
};
static const char *const vfr_1_groups[] = {
	"gpio117",
};
static const char *const vsense_trigger_mirnat_groups[] = {
	"gpio52",
};
static const char *const wcn_sw_ctrl_groups[] = {
	"gpio81",
};

static const struct pinfunction kera_functions[] = {
	MSM_PIN_FUNCTION(gpio),
	MSM_PIN_FUNCTION(SDC2_CLK),
	MSM_PIN_FUNCTION(SDC2_CMD),
	MSM_PIN_FUNCTION(SDC2_DATA0),
	MSM_PIN_FUNCTION(SDC2_DATA1),
	MSM_PIN_FUNCTION(SDC2_DATA2),
	MSM_PIN_FUNCTION(SDC2_DATA3),
	MSM_PIN_FUNCTION(aoss_cti),
	MSM_PIN_FUNCTION(atest_char0),
	MSM_PIN_FUNCTION(atest_char1),
	MSM_PIN_FUNCTION(atest_char2),
	MSM_PIN_FUNCTION(atest_char3),
	MSM_PIN_FUNCTION(atest_char_start),
	MSM_PIN_FUNCTION(atest_usb00),
	MSM_PIN_FUNCTION(atest_usb01),
	MSM_PIN_FUNCTION(audio_ext_mclk0),
	MSM_PIN_FUNCTION(audio_ref_clk),
	MSM_PIN_FUNCTION(cam_mclk),
	MSM_PIN_FUNCTION(cci_async_in0),
	MSM_PIN_FUNCTION(cci_async_in1),
	MSM_PIN_FUNCTION(cci_async_in2),
	MSM_PIN_FUNCTION(cci_i2c_scl0),
	MSM_PIN_FUNCTION(cci_i2c_scl1),
	MSM_PIN_FUNCTION(cci_i2c_scl2),
	MSM_PIN_FUNCTION(cci_i2c_scl3),
	MSM_PIN_FUNCTION(cci_i2c_sda0),
	MSM_PIN_FUNCTION(cci_i2c_sda1),
	MSM_PIN_FUNCTION(cci_i2c_sda2),
	MSM_PIN_FUNCTION(cci_i2c_sda3),
	MSM_PIN_FUNCTION(cci_timer0),
	MSM_PIN_FUNCTION(cci_timer1),
	MSM_PIN_FUNCTION(cci_timer2),
	MSM_PIN_FUNCTION(cci_timer3),
	MSM_PIN_FUNCTION(cci_timer4),
	MSM_PIN_FUNCTION(coex_uart1_rx),
	MSM_PIN_FUNCTION(coex_uart1_tx),
	MSM_PIN_FUNCTION(coex_uart2_rx),
	MSM_PIN_FUNCTION(coex_uart2_tx),
	MSM_PIN_FUNCTION(dbg_out_clk),
	MSM_PIN_FUNCTION(ddr_bist_complete),
	MSM_PIN_FUNCTION(ddr_bist_fail),
	MSM_PIN_FUNCTION(ddr_bist_start),
	MSM_PIN_FUNCTION(ddr_bist_stop),
	MSM_PIN_FUNCTION(ddr_pxi0),
	MSM_PIN_FUNCTION(ddr_pxi1),
	MSM_PIN_FUNCTION(dp0_hot),
	MSM_PIN_FUNCTION(gcc_gp1),
	MSM_PIN_FUNCTION(gcc_gp2),
	MSM_PIN_FUNCTION(gcc_gp3),
	MSM_PIN_FUNCTION(gnss_adc0),
	MSM_PIN_FUNCTION(gnss_adc1),
	MSM_PIN_FUNCTION(hdmi_ddc_scl),
	MSM_PIN_FUNCTION(hdmi_ddc_sda),
	MSM_PIN_FUNCTION(hdmi_dtest0),
	MSM_PIN_FUNCTION(hdmi_dtest1),
	MSM_PIN_FUNCTION(hdmi_hot_plug),
	MSM_PIN_FUNCTION(hdmi_pixel_clk),
	MSM_PIN_FUNCTION(hdmi_rcv_det),
	MSM_PIN_FUNCTION(hdmi_tx_cec),
	MSM_PIN_FUNCTION(host2wlan_sol),
	MSM_PIN_FUNCTION(i2s0_data0),
	MSM_PIN_FUNCTION(i2s0_data1),
	MSM_PIN_FUNCTION(i2s0_sck),
	MSM_PIN_FUNCTION(i2s0_ws),
	MSM_PIN_FUNCTION(ibi_i3c),
	MSM_PIN_FUNCTION(jitter_bist),
	MSM_PIN_FUNCTION(mdp_esync0_out),
	MSM_PIN_FUNCTION(mdp_esync1_out),
	MSM_PIN_FUNCTION(mdp_vsync),
	MSM_PIN_FUNCTION(mdp_vsync0_out),
	MSM_PIN_FUNCTION(mdp_vsync11_out),
	MSM_PIN_FUNCTION(mdp_vsync1_out),
	MSM_PIN_FUNCTION(mdp_vsync2_out),
	MSM_PIN_FUNCTION(mdp_vsync3_out),
	MSM_PIN_FUNCTION(mdp_vsync_e),
	MSM_PIN_FUNCTION(nav_gpio0),
	MSM_PIN_FUNCTION(nav_gpio1),
	MSM_PIN_FUNCTION(nav_gpio2),
	MSM_PIN_FUNCTION(nav_gpio3),
	MSM_PIN_FUNCTION(pcie0_clk_req_n),
	MSM_PIN_FUNCTION(pcie1_clk_req_n),
	MSM_PIN_FUNCTION(phase_flag0),
	MSM_PIN_FUNCTION(phase_flag1),
	MSM_PIN_FUNCTION(phase_flag10),
	MSM_PIN_FUNCTION(phase_flag11),
	MSM_PIN_FUNCTION(phase_flag12),
	MSM_PIN_FUNCTION(phase_flag13),
	MSM_PIN_FUNCTION(phase_flag14),
	MSM_PIN_FUNCTION(phase_flag15),
	MSM_PIN_FUNCTION(phase_flag16),
	MSM_PIN_FUNCTION(phase_flag17),
	MSM_PIN_FUNCTION(phase_flag18),
	MSM_PIN_FUNCTION(phase_flag19),
	MSM_PIN_FUNCTION(phase_flag2),
	MSM_PIN_FUNCTION(phase_flag20),
	MSM_PIN_FUNCTION(phase_flag21),
	MSM_PIN_FUNCTION(phase_flag22),
	MSM_PIN_FUNCTION(phase_flag23),
	MSM_PIN_FUNCTION(phase_flag24),
	MSM_PIN_FUNCTION(phase_flag25),
	MSM_PIN_FUNCTION(phase_flag26),
	MSM_PIN_FUNCTION(phase_flag27),
	MSM_PIN_FUNCTION(phase_flag28),
	MSM_PIN_FUNCTION(phase_flag29),
	MSM_PIN_FUNCTION(phase_flag3),
	MSM_PIN_FUNCTION(phase_flag30),
	MSM_PIN_FUNCTION(phase_flag31),
	MSM_PIN_FUNCTION(phase_flag4),
	MSM_PIN_FUNCTION(phase_flag5),
	MSM_PIN_FUNCTION(phase_flag6),
	MSM_PIN_FUNCTION(phase_flag7),
	MSM_PIN_FUNCTION(phase_flag8),
	MSM_PIN_FUNCTION(phase_flag9),
	MSM_PIN_FUNCTION(pll_bist_sync),
	MSM_PIN_FUNCTION(pll_clk_aux),
	MSM_PIN_FUNCTION(prng_rosc0),
	MSM_PIN_FUNCTION(prng_rosc1),
	MSM_PIN_FUNCTION(prng_rosc2),
	MSM_PIN_FUNCTION(prng_rosc3),
	MSM_PIN_FUNCTION(qdss_cti),
	MSM_PIN_FUNCTION(qdss_gpio),
	MSM_PIN_FUNCTION(qdss_gpio0),
	MSM_PIN_FUNCTION(qdss_gpio1),
	MSM_PIN_FUNCTION(qdss_gpio10),
	MSM_PIN_FUNCTION(qdss_gpio11),
	MSM_PIN_FUNCTION(qdss_gpio12),
	MSM_PIN_FUNCTION(qdss_gpio13),
	MSM_PIN_FUNCTION(qdss_gpio14),
	MSM_PIN_FUNCTION(qdss_gpio15),
	MSM_PIN_FUNCTION(qdss_gpio2),
	MSM_PIN_FUNCTION(qdss_gpio3),
	MSM_PIN_FUNCTION(qdss_gpio4),
	MSM_PIN_FUNCTION(qdss_gpio5),
	MSM_PIN_FUNCTION(qdss_gpio6),
	MSM_PIN_FUNCTION(qdss_gpio7),
	MSM_PIN_FUNCTION(qdss_gpio8),
	MSM_PIN_FUNCTION(qdss_gpio9),
	MSM_PIN_FUNCTION(qlink_big_enable),
	MSM_PIN_FUNCTION(qlink_big_request),
	MSM_PIN_FUNCTION(qlink_little_enable),
	MSM_PIN_FUNCTION(qlink_little_request),
	MSM_PIN_FUNCTION(qlink_wmss),
	MSM_PIN_FUNCTION(qspi0_clk),
	MSM_PIN_FUNCTION(qspi0_cs0_n),
	MSM_PIN_FUNCTION(qspi0_cs1_n),
	MSM_PIN_FUNCTION(qspi0_data0),
	MSM_PIN_FUNCTION(qspi0_data1),
	MSM_PIN_FUNCTION(qspi0_data2),
	MSM_PIN_FUNCTION(qspi0_data3),
	MSM_PIN_FUNCTION(qup1_se0_l0),
	MSM_PIN_FUNCTION(qup1_se0_l1),
	MSM_PIN_FUNCTION(qup1_se0_l2),
	MSM_PIN_FUNCTION(qup1_se0_l3),
	MSM_PIN_FUNCTION(qup1_se1_l0),
	MSM_PIN_FUNCTION(qup1_se1_l1),
	MSM_PIN_FUNCTION(qup1_se1_l2),
	MSM_PIN_FUNCTION(qup1_se1_l3),
	MSM_PIN_FUNCTION(qup1_se2_l0),
	MSM_PIN_FUNCTION(qup1_se2_l1),
	MSM_PIN_FUNCTION(qup1_se2_l2_mira),
	MSM_PIN_FUNCTION(qup1_se2_l2_mirb),
	MSM_PIN_FUNCTION(qup1_se2_l3_mira),
	MSM_PIN_FUNCTION(qup1_se2_l3_mirb),
	MSM_PIN_FUNCTION(qup1_se2_l4),
	MSM_PIN_FUNCTION(qup1_se2_l5),
	MSM_PIN_FUNCTION(qup1_se2_l6),
	MSM_PIN_FUNCTION(qup1_se3_l0),
	MSM_PIN_FUNCTION(qup1_se3_l1),
	MSM_PIN_FUNCTION(qup1_se3_l2),
	MSM_PIN_FUNCTION(qup1_se3_l3),
	MSM_PIN_FUNCTION(qup1_se4_l0),
	MSM_PIN_FUNCTION(qup1_se4_l1),
	MSM_PIN_FUNCTION(qup1_se4_l2),
	MSM_PIN_FUNCTION(qup1_se4_l3),
	MSM_PIN_FUNCTION(qup1_se5_l0),
	MSM_PIN_FUNCTION(qup1_se5_l1),
	MSM_PIN_FUNCTION(qup1_se5_l2),
	MSM_PIN_FUNCTION(qup1_se5_l3),
	MSM_PIN_FUNCTION(qup1_se5_l4),
	MSM_PIN_FUNCTION(qup1_se5_l5),
	MSM_PIN_FUNCTION(qup1_se6_l0),
	MSM_PIN_FUNCTION(qup1_se6_l1_mira),
	MSM_PIN_FUNCTION(qup1_se6_l1_mirb),
	MSM_PIN_FUNCTION(qup1_se6_l2),
	MSM_PIN_FUNCTION(qup1_se6_l3_mira),
	MSM_PIN_FUNCTION(qup1_se6_l3_mirb),
	MSM_PIN_FUNCTION(qup1_se7_l0_mira),
	MSM_PIN_FUNCTION(qup1_se7_l0_mirb),
	MSM_PIN_FUNCTION(qup1_se7_l1_mira),
	MSM_PIN_FUNCTION(qup1_se7_l1_mirb),
	MSM_PIN_FUNCTION(qup1_se7_l2),
	MSM_PIN_FUNCTION(qup1_se7_l3),
	MSM_PIN_FUNCTION(qup2_se0_l0),
	MSM_PIN_FUNCTION(qup2_se0_l1),
	MSM_PIN_FUNCTION(qup2_se0_l2),
	MSM_PIN_FUNCTION(qup2_se0_l3),
	MSM_PIN_FUNCTION(qup2_se1_l0),
	MSM_PIN_FUNCTION(qup2_se1_l1),
	MSM_PIN_FUNCTION(qup2_se1_l2),
	MSM_PIN_FUNCTION(qup2_se1_l3),
	MSM_PIN_FUNCTION(qup2_se2_l0),
	MSM_PIN_FUNCTION(qup2_se2_l1),
	MSM_PIN_FUNCTION(qup2_se2_l2),
	MSM_PIN_FUNCTION(qup2_se2_l3),
	MSM_PIN_FUNCTION(qup2_se2_l4),
	MSM_PIN_FUNCTION(qup2_se2_l5),
	MSM_PIN_FUNCTION(qup2_se2_l6),
	MSM_PIN_FUNCTION(qup2_se3_l0_mira),
	MSM_PIN_FUNCTION(qup2_se3_l0_mirb),
	MSM_PIN_FUNCTION(qup2_se3_l1_mira),
	MSM_PIN_FUNCTION(qup2_se3_l1_mirb),
	MSM_PIN_FUNCTION(qup2_se3_l2),
	MSM_PIN_FUNCTION(qup2_se3_l3),
	MSM_PIN_FUNCTION(qup2_se4_l0),
	MSM_PIN_FUNCTION(qup2_se4_l1),
	MSM_PIN_FUNCTION(qup2_se4_l2),
	MSM_PIN_FUNCTION(qup2_se4_l3),
	MSM_PIN_FUNCTION(qup2_se5_l0),
	MSM_PIN_FUNCTION(qup2_se5_l1),
	MSM_PIN_FUNCTION(qup2_se5_l2),
	MSM_PIN_FUNCTION(qup2_se5_l3),
	MSM_PIN_FUNCTION(qup2_se6_l0),
	MSM_PIN_FUNCTION(qup2_se6_l1),
	MSM_PIN_FUNCTION(qup2_se6_l2),
	MSM_PIN_FUNCTION(qup2_se6_l3),
	MSM_PIN_FUNCTION(qup2_se7_l0),
	MSM_PIN_FUNCTION(qup2_se7_l1),
	MSM_PIN_FUNCTION(qup2_se7_l2),
	MSM_PIN_FUNCTION(qup2_se7_l3),
	MSM_PIN_FUNCTION(resout_gpio),
	MSM_PIN_FUNCTION(sd_write_protect),
	MSM_PIN_FUNCTION(sdc1None),
	MSM_PIN_FUNCTION(sdc1_clk),
	MSM_PIN_FUNCTION(sdc1_cmd),
	MSM_PIN_FUNCTION(sdc1_rclk),
	MSM_PIN_FUNCTION(sdc2_fb_clk),
	MSM_PIN_FUNCTION(tb_trig_sdc1),
	MSM_PIN_FUNCTION(tb_trig_sdc2),
	MSM_PIN_FUNCTION(tmess_prng0),
	MSM_PIN_FUNCTION(tmess_prng1),
	MSM_PIN_FUNCTION(tmess_prng2),
	MSM_PIN_FUNCTION(tmess_prng3),
	MSM_PIN_FUNCTION(tsense_pwm1),
	MSM_PIN_FUNCTION(tsense_pwm2),
	MSM_PIN_FUNCTION(tsense_pwm3),
	MSM_PIN_FUNCTION(tsense_pwm4),
	MSM_PIN_FUNCTION(uim0_clk),
	MSM_PIN_FUNCTION(uim0_data),
	MSM_PIN_FUNCTION(uim0_present),
	MSM_PIN_FUNCTION(uim0_reset),
	MSM_PIN_FUNCTION(uim1_clk_mira),
	MSM_PIN_FUNCTION(uim1_clk_mirb),
	MSM_PIN_FUNCTION(uim1_data_mira),
	MSM_PIN_FUNCTION(uim1_data_mirb),
	MSM_PIN_FUNCTION(uim1_present_mira),
	MSM_PIN_FUNCTION(uim1_present_mirb),
	MSM_PIN_FUNCTION(uim1_reset_mira),
	MSM_PIN_FUNCTION(uim1_reset_mirb),
	MSM_PIN_FUNCTION(usb0_hs),
	MSM_PIN_FUNCTION(usb0_phy_ps),
	MSM_PIN_FUNCTION(vfr_0),
	MSM_PIN_FUNCTION(vfr_1),
	MSM_PIN_FUNCTION(vsense_trigger_mirnat),
	MSM_PIN_FUNCTION(wcn_sw_ctrl),
};

/* Every pin is maintained as a single group, and missing or non-existing pin
 * would be maintained as dummy group to synchronize pin group index with
 * pin descriptor registered with pinctrl core.
 * Clients would not be able to request these dummy pin groups.
 */
static const struct msm_pingroup kera_groups[] = {
	[0] = PINGROUP(0, qup2_se0_l0, ibi_i3c, aoss_cti, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[1] = PINGROUP(1, qup2_se0_l1, ibi_i3c, aoss_cti, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[2] = PINGROUP(2, qup2_se0_l2, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[3] = PINGROUP(3, qup2_se0_l3, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[4] = PINGROUP(4, qup2_se1_l0, ibi_i3c, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[5] = PINGROUP(5, qup2_se1_l1, ibi_i3c, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[6] = PINGROUP(6, qup2_se1_l2, hdmi_ddc_scl, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[7] = PINGROUP(7, qup2_se1_l3, hdmi_ddc_sda, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[8] = PINGROUP(8, qup2_se2_l0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[9] = PINGROUP(9, qup2_se2_l1, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[10] = PINGROUP(10, qup2_se2_l2, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[11] = PINGROUP(11, qup2_se2_l3, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[12] = PINGROUP(12, qup2_se4_l0, ibi_i3c, mdp_esync1_out, qup2_se7_l3,
		       NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[13] = PINGROUP(13, qup2_se4_l1, ibi_i3c, mdp_vsync_e, mdp_esync0_out,
		       qup2_se7_l2, NA, NA, NA, NA, NA, NA, 0, -1),
	[14] = PINGROUP(14, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[15] = PINGROUP(15, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[16] = PINGROUP(16, qup2_se5_l0, qup2_se2_l4, mdp_vsync, mdp_vsync2_out,
		       mdp_vsync3_out, NA, NA, NA, NA, NA, NA, 0, -1),
	[17] = PINGROUP(17, qup2_se5_l1, qup2_se2_l5, mdp_vsync, mdp_vsync0_out,
		       mdp_vsync1_out, NA, NA, NA, NA, NA, NA, 0, -1),
	[18] = PINGROUP(18, qup2_se5_l2, qup2_se2_l6, hdmi_pixel_clk, NA,
		       qdss_cti, NA, NA, NA, NA, NA, NA, 0, -1),
	[19] = PINGROUP(19, qup2_se5_l3, hdmi_rcv_det, NA, qdss_cti, NA, NA, NA,
		       NA, NA, NA, NA, 0, -1),
	[20] = PINGROUP(20, qup2_se6_l0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[21] = PINGROUP(21, qup2_se6_l1, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[22] = PINGROUP(22, qup2_se6_l2, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[23] = PINGROUP(23, qup2_se6_l3, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[24] = PINGROUP(24, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[25] = PINGROUP(25, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[26] = PINGROUP(26, qup2_se4_l2, aoss_cti, qup2_se7_l1, NA, NA, NA, NA,
		       NA, NA, NA, NA, 0, -1),
	[27] = PINGROUP(27, qup2_se4_l3, aoss_cti, mdp_vsync11_out, qup2_se7_l0,
		       gcc_gp1, NA, NA, NA, NA, NA, NA, 0, -1),
	[28] = PINGROUP(28, qup1_se0_l0, ibi_i3c, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[29] = PINGROUP(29, qup1_se0_l1, ibi_i3c, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[30] = PINGROUP(30, qup1_se0_l2, qup1_se2_l6, cci_async_in2, gcc_gp3,
		       qdss_gpio0, NA, NA, NA, NA, NA, NA, 0, -1),
	[31] = PINGROUP(31, qup1_se0_l3, cci_async_in1, qdss_gpio1, NA, NA, NA,
		       NA, NA, NA, NA, NA, 0, -1),
	[32] = PINGROUP(32, qup1_se1_l0, ibi_i3c, audio_ref_clk, gcc_gp2,
		       qdss_cti, NA, NA, NA, NA, NA, NA, 0, -1),
	[33] = PINGROUP(33, qup1_se1_l1, ibi_i3c, host2wlan_sol, gcc_gp3, NA,
		       NA, NA, NA, NA, NA, NA, 0, -1),
	[34] = PINGROUP(34, qup1_se1_l2, qup1_se5_l4, tb_trig_sdc1, ddr_bist_start,
		       qdss_gpio2, NA, NA, NA, NA, NA, NA, 0, -1),
	[35] = PINGROUP(35, qup1_se1_l3, qup1_se5_l5, tb_trig_sdc2, gcc_gp2,
		       qdss_gpio3, NA, NA, NA, NA, NA, NA, 0, -1),
	[36] = PINGROUP(36, qup1_se4_l0, qup1_se4_l3, ibi_i3c, NA, NA, NA, NA,
		       NA, NA, NA, NA, 0, -1),
	[37] = PINGROUP(37, qup1_se4_l1, qup1_se4_l2, ibi_i3c, NA, NA, NA, NA,
		       NA, NA, NA, NA, 0, -1),
	[38] = PINGROUP(38, SDC2_DATA0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[39] = PINGROUP(39, SDC2_DATA1, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[40] = PINGROUP(40, qup1_se6_l0, qup1_se2_l4, qup1_se6_l3_mira, NA,
		       qdss_gpio7, gnss_adc1, ddr_pxi1, NA, NA, NA, NA, 0, -1),
	[41] = PINGROUP(41, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[42] = PINGROUP(42, qup1_se6_l2, qup1_se2_l5, qup1_se6_l1_mira, qdss_gpio6,
		       gnss_adc0, ddr_pxi1, NA, NA, NA, NA, NA, 0, -1),
	[43] = PINGROUP(43, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[44] = PINGROUP(44, qup1_se3_l0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[45] = PINGROUP(45, qup1_se3_l1, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[46] = PINGROUP(46, qup1_se3_l2, hdmi_tx_cec, NA, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[47] = PINGROUP(47, qup1_se3_l3, hdmi_hot_plug, NA, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[48] = PINGROUP(48, SDC2_DATA2, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[49] = PINGROUP(49, SDC2_DATA3, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[50] = PINGROUP(50, sdc2_fb_clk, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[51] = PINGROUP(51, SDC2_CMD, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0,
		       -1),
	[52] = PINGROUP(52, qup1_se2_l0, pcie1_clk_req_n, qup1_se2_l2_mirb,
		       ddr_bist_complete, qdss_gpio12, NA,
		       vsense_trigger_mirnat, NA, NA, NA, NA, 0, -1),
	[53] = PINGROUP(53, qup1_se2_l1, qup1_se2_l3_mirb, gcc_gp1, ddr_bist_stop,
		       NA, qdss_gpio11, NA, NA, NA, NA, NA, 0, -1),
	[54] = PINGROUP(54, qup1_se2_l2_mira, qup1_se6_l1_mirb, qdss_gpio,
		       gnss_adc1, atest_usb01, ddr_pxi0, NA, NA, NA, NA, NA, 0,
		       -1),
	[55] = PINGROUP(55, qup1_se2_l3_mira, dp0_hot, qup1_se6_l3_mirb, NA,
		       gnss_adc0, atest_usb00, ddr_pxi0, NA, NA, NA, NA, 0, -1),
	[56] = PINGROUP(56, usb0_hs, tsense_pwm1, tsense_pwm2, tsense_pwm3,
		       tsense_pwm4, NA, NA, NA, NA, NA, NA, 0, -1),
	[57] = PINGROUP(57, sd_write_protect, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[58] = PINGROUP(58, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[59] = PINGROUP(59, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[60] = PINGROUP(60, i2s0_sck, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0,
		       -1),
	[61] = PINGROUP(61, i2s0_ws, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0,
		       -1),
	[62] = PINGROUP(62, SDC2_CLK, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0,
		       -1),
	[63] = PINGROUP(63, resout_gpio, i2s0_data1, cci_timer1, vfr_0, NA, NA,
		       NA, NA, NA, NA, NA, 0, -1),
	[64] = PINGROUP(64, i2s0_data0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[65] = PINGROUP(65, cam_mclk, NA, qdss_gpio13, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[66] = PINGROUP(66, cam_mclk, NA, qdss_gpio14, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[67] = PINGROUP(67, cam_mclk, prng_rosc0, NA, qdss_gpio10, NA, NA, NA,
		       NA, NA, NA, NA, 0, -1),
	[68] = PINGROUP(68, cam_mclk, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0,
		       -1),
	[69] = PINGROUP(69, cam_mclk, audio_ext_mclk0, resout_gpio, prng_rosc1,
		       NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[70] = PINGROUP(70, cci_i2c_sda0, tmess_prng2, NA, phase_flag1,
		       atest_char1, NA, NA, NA, NA, NA, NA, 0, -1),
	[71] = PINGROUP(71, cci_i2c_scl0, tmess_prng3, NA, phase_flag0,
		       atest_char0, NA, NA, NA, NA, NA, NA, 0, -1),
	[72] = PINGROUP(72, cci_i2c_sda1, tmess_prng1, qdss_gpio, atest_char2,
		       NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[73] = PINGROUP(73, cci_i2c_scl1, tmess_prng0, qdss_cti,
		       atest_char_start, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[74] = PINGROUP(74, cci_i2c_sda2, prng_rosc3, qdss_cti, atest_char3, NA,
		       NA, NA, NA, NA, NA, NA, 0, -1),
	[75] = PINGROUP(75, cci_i2c_scl2, NA, phase_flag31, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[76] = PINGROUP(76, cci_i2c_sda3, cci_timer0, prng_rosc2, NA,
		       phase_flag30, NA, NA, NA, NA, NA, NA, 0, -1),
	[77] = PINGROUP(77, cci_i2c_scl3, jitter_bist, NA, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[78] = PINGROUP(78, qup1_se7_l3, qup1_se7_l0_mirb, NA, phase_flag29, NA,
		       NA, NA, NA, NA, NA, NA, 0, -1),
	[79] = PINGROUP(79, qspi0_clk, mdp_vsync, qup2_se3_l0_mira, NA, NA, NA,
		       NA, NA, NA, NA, NA, 0, -1),
	[80] = PINGROUP(80, pcie0_clk_req_n, qup1_se7_l1_mira, NA, phase_flag28,
		       NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[81] = PINGROUP(81, wcn_sw_ctrl, qup1_se7_l0_mira, dbg_out_clk, NA, NA,
		       NA, NA, NA, NA, NA, NA, 0, -1),
	[82] = PINGROUP(82, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[83] = PINGROUP(83, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[84] = PINGROUP(84, uim0_data, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[85] = PINGROUP(85, uim0_clk, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0,
		       -1),
	[86] = PINGROUP(86, uim0_reset, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[87] = PINGROUP(87, uim0_present, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[88] = PINGROUP(88, uim1_data_mirb, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[89] = PINGROUP(89, uim1_clk_mirb, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[90] = PINGROUP(90, uim1_reset_mirb, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[91] = PINGROUP(91, uim1_present_mirb, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[92] = PINGROUP(92, qlink_little_request, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[93] = PINGROUP(93, qlink_little_enable, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[94] = PINGROUP(94, qlink_wmss, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[95] = PINGROUP(95, qlink_big_request, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[96] = PINGROUP(96, qlink_big_enable, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[97] = PINGROUP(97, uim1_data_mira, qspi0_data0, qup2_se3_l1_mira, NA,
		       NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[98] = PINGROUP(98, uim1_clk_mira, qspi0_data1, NA, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[99] = PINGROUP(99, uim1_reset_mira, qspi0_data2, NA, NA, NA, NA, NA,
		       NA, NA, NA, NA, 0, -1),
	[100] = PINGROUP(100, uim1_present_mira, qspi0_data3, qup2_se3_l2,
		       coex_uart2_tx, qup2_se3_l1_mirb, mdp_vsync, NA, NA, NA,
		       NA, NA, 0, -1),
	[101] = PINGROUP(101, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[102] = PINGROUP(102, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[103] = PINGROUP(103, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[104] = PINGROUP(104, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[105] = PINGROUP(105, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[106] = PINGROUP(106, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[107] = PINGROUP(107, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[108] = PINGROUP(108, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[109] = PINGROUP(109, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[110] = PINGROUP(110, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[111] = PINGROUP(111, coex_uart1_tx, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[112] = PINGROUP(112, coex_uart1_rx, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[113] = PINGROUP(113, NA, nav_gpio3, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[114] = PINGROUP(114, qup1_se7_l2, qup1_se7_l1_mirb, NA, qdss_gpio15,
		       NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[115] = PINGROUP(115, NA, qspi0_cs1_n, cci_async_in0, NA, NA, NA, NA,
		       NA, NA, NA, NA, 0, -1),
	[116] = PINGROUP(116, qspi0_cs0_n, coex_uart2_rx, qup2_se3_l3,
		       qup2_se3_l0_mirb, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[117] = PINGROUP(117, nav_gpio1, NA, vfr_1, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[118] = PINGROUP(118, nav_gpio2, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[119] = PINGROUP(119, nav_gpio0, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[120] = PINGROUP(120, sdc1_rclk, mdp_vsync, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[121] = PINGROUP(121, sdc1_clk, mdp_vsync, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[122] = PINGROUP(122, usb0_phy_ps, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[123] = PINGROUP(123, sdc1_cmd, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[124] = PINGROUP(124, sdc1None, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[125] = PINGROUP(125, sdc1None, cci_timer2, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[126] = PINGROUP(126, sdc1None, cci_timer3, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[127] = PINGROUP(127, sdc1None, cci_timer4, NA, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[128] = PINGROUP(128, sdc1None, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[129] = PINGROUP(129, sdc1None, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[130] = PINGROUP(130, sdc1None, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[131] = PINGROUP(131, sdc1None, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[132] = PINGROUP(132, qup1_se5_l0, NA, qdss_gpio8, hdmi_dtest0, NA, NA,
		       NA, NA, NA, NA, NA, 0, -1),
	[133] = PINGROUP(133, qup1_se5_l1, NA, qdss_gpio9, hdmi_dtest1, NA, NA,
		       NA, NA, NA, NA, NA, 0, -1),
	[134] = PINGROUP(134, qup1_se5_l2, qdss_gpio5, NA, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[135] = PINGROUP(135, qup1_se5_l3, NA, pll_clk_aux, qdss_gpio4, NA, NA,
		       NA, NA, NA, NA, NA, 0, -1),
	[136] = PINGROUP(136, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[137] = PINGROUP(137, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[138] = PINGROUP(138, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[139] = PINGROUP(139, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[140] = PINGROUP(140, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[141] = PINGROUP(141, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[142] = PINGROUP(142, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[143] = PINGROUP(143, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[144] = PINGROUP(144, NA, qdss_gpio, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[145] = PINGROUP(145, qdss_gpio9, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[146] = PINGROUP(146, NA, qdss_gpio7, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[147] = PINGROUP(147, ddr_bist_fail, NA, qdss_gpio, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[148] = PINGROUP(148, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[149] = PINGROUP(149, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[150] = PINGROUP(150, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[151] = PINGROUP(151, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[152] = PINGROUP(152, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[153] = PINGROUP(153, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[154] = PINGROUP(154, qdss_cti, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,
		       0, -1),
	[155] = PINGROUP(155, NA, qdss_gpio15, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[156] = PINGROUP(156, NA, qdss_gpio6, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[157] = PINGROUP(157, NA, phase_flag27, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[158] = PINGROUP(158, NA, phase_flag26, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[159] = PINGROUP(159, NA, phase_flag25, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[160] = PINGROUP(160, NA, phase_flag24, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[161] = PINGROUP(161, NA, phase_flag23, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[162] = PINGROUP(162, NA, phase_flag22, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[163] = PINGROUP(163, NA, phase_flag21, qdss_gpio0, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[164] = PINGROUP(164, NA, phase_flag20, qdss_gpio1, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[165] = PINGROUP(165, NA, phase_flag19, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[166] = PINGROUP(166, NA, phase_flag18, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[167] = PINGROUP(167, NA, phase_flag17, qdss_gpio2, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[168] = PINGROUP(168, NA, phase_flag16, qdss_gpio3, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[169] = PINGROUP(169, NA, phase_flag15, qdss_gpio4, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[170] = PINGROUP(170, NA, phase_flag14, qdss_gpio5, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[171] = PINGROUP(171, NA, phase_flag13, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[172] = PINGROUP(172, NA, phase_flag12, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[173] = PINGROUP(173, NA, phase_flag9, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[174] = PINGROUP(174, NA, phase_flag10, NA, NA, NA, NA, NA, NA, NA, NA,
		       NA, 0, -1),
	[175] = PINGROUP(175, resout_gpio, NA, phase_flag11, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[176] = PINGROUP(176, NA, phase_flag8, qdss_cti, NA, NA, NA, NA, NA, NA,
		       NA, NA, 0, -1),
	[177] = PINGROUP(177, NA, phase_flag7, qdss_gpio14, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[178] = PINGROUP(178, NA, phase_flag6, qdss_gpio8, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[179] = PINGROUP(179, NA, phase_flag5, qdss_gpio10, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[180] = PINGROUP(180, NA, phase_flag4, qdss_gpio11, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[181] = PINGROUP(181, NA, phase_flag3, qdss_gpio12, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[182] = PINGROUP(182, NA, phase_flag2, qdss_gpio13, NA, NA, NA, NA, NA,
		       NA, NA, NA, 0, -1),
	[183] = PINGROUP(183, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 0, -1),
	[184] = UFS_RESET(ufs_reset, 0x1C9004, 0x1CA000),
};

static struct pinctrl_qup kera_qup_regs[] = {
	QUP_I3C(1, QUP_1_I3C_0_MODE_OFFSET),
	QUP_I3C(2, QUP_1_I3C_1_MODE_OFFSET),
	QUP_I3C(3, QUP_1_I3C_4_MODE_OFFSET),
	QUP_I3C(4, QUP_1_I3C_6_MODE_OFFSET),
	QUP_I3C(5, QUP_2_I3C_0_MODE_OFFSET),
	QUP_I3C(6, QUP_2_I3C_1_MODE_OFFSET),
	QUP_I3C(7, QUP_2_I3C_2_MODE_OFFSET),
	QUP_I3C(8, QUP_2_I3C_3_MODE_OFFSET),
	QUP_I3C(9, QUP_2_I3C_4_MODE_OFFSET),
	QUP_I3C(10, QUP_2_I3C_6_MODE_OFFSET),
};

static const struct msm_gpio_wakeirq_map kera_pdc_map[] = {
	{ 0, 82 }, { 3, 87 }, { 4, 90 }, { 6, 68 }, { 7, 153 }, { 11, 85 },
	{ 12, 107 }, { 13, 106 }, { 16, 88 }, { 17, 70 }, { 18, 134 }, { 19, 79 },
	{ 23, 80 }, { 26, 91 }, { 27, 74 }, { 28, 137 }, { 29, 138 }, { 30, 139 },
	{ 31, 140 }, { 32, 117 }, { 34, 100 }, { 35, 98 }, { 36, 141 }, { 39, 89 },
	{ 40, 142 }, { 42, 143 }, { 44, 101 }, { 45, 144 }, { 46, 145 }, { 47, 146 },
	{ 49, 75 }, { 51, 147 }, { 52, 148 }, { 53, 149 }, { 54, 150 }, { 55, 151 },
	{ 56, 152 }, { 58, 71 }, { 59, 155 }, { 63, 99 }, { 78, 156 }, { 79, 76 },
	{ 80, 157 }, { 81, 69 }, { 87, 158 }, { 91, 67 }, { 92, 159 }, { 95, 160 },
	{ 98, 161 }, { 99, 162 }, { 100, 83 }, { 108, 154 }, { 109, 84 }, { 112, 86 },
	{ 113, 92 }, { 114, 93 }, { 115, 110 }, { 116, 94 }, { 117, 77 }, { 118, 108 },
	{ 119, 95 }, { 120, 81 }, { 121, 96 }, { 122, 97 }, { 123, 102 }, { 125, 103 },
	{ 127, 104 }, { 128, 105 }, { 129, 78 }, { 130, 112 }, { 131, 113 }, { 133, 114 },
	{ 135, 115 }, { 139, 116 }, { 142, 118 }, { 145, 109 }, { 147, 72 }, { 149, 111 },
	{ 154, 122 }, { 157, 119 }, { 159, 120 }, { 161, 121 }, { 164, 123 }, { 165, 124 },
	{ 167, 125 }, { 170, 126 }, { 171, 73 }, { 172, 127 }, { 173, 128 }, { 174, 129 },
	{ 175, 130 }, { 176, 131 }, { 177, 132 }, { 179, 133 }, { 182, 135 }, { 184, 136 },
};

static const struct msm_pinctrl_soc_data kera_pinctrl = {
	.pins = kera_pins,
	.npins = ARRAY_SIZE(kera_pins),
	.functions = kera_functions,
	.nfunctions = ARRAY_SIZE(kera_functions),
	.groups = kera_groups,
	.ngroups = ARRAY_SIZE(kera_groups),
	.ngpios = 185,
	.qup_regs = kera_qup_regs,
	.nqup_regs = ARRAY_SIZE(kera_qup_regs),
	.wakeirq_map = kera_pdc_map,
	.nwakeirq_map = ARRAY_SIZE(kera_pdc_map),
	.egpio_func = 11,
};

static const struct of_device_id kera_pinctrl_of_match[] = {
	{ .compatible = "qcom,kera-tlmm", .data = &kera_pinctrl},
	{},
};

static int kera_pinctrl_probe(struct platform_device *pdev)
{
	const struct msm_pinctrl_soc_data *pinctrl_data;
	struct device *dev = &pdev->dev;

	pinctrl_data = of_device_get_match_data(dev);
	if (!pinctrl_data)
		return -EINVAL;

	return msm_pinctrl_probe(pdev, pinctrl_data);
}

static struct platform_driver kera_pinctrl_driver = {
	.driver = {
		.name = "kera-pinctrl",
		.of_match_table = kera_pinctrl_of_match,
	},
	.probe = kera_pinctrl_probe,
	.remove = msm_pinctrl_remove,
};

static int __init kera_pinctrl_init(void)
{
	return platform_driver_register(&kera_pinctrl_driver);
}
arch_initcall(kera_pinctrl_init);

static void __exit kera_pinctrl_exit(void)
{
	platform_driver_unregister(&kera_pinctrl_driver);
}
module_exit(kera_pinctrl_exit);

MODULE_DESCRIPTION("QTI kera pinctrl driver");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(of, kera_pinctrl_of_match);
