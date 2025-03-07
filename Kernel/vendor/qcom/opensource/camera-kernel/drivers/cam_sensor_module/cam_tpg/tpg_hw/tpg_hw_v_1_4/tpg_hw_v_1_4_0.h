/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2021-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __TPG_HW_V_1_4_0_H__
#define __TPG_HW_V_1_4_0_H__


struct cam_tpg_ver_1_4_reg_offset cam_tpg104_reg = {
	/* Register offsets below */
	.hw_version = 0x0,
	.hw_status = 0x4,
	.dmi_cfg = 0x8,
	.dmi_lut_cfg = 0xc,
	.dmi_data = 0x10,
	.dmi_data_1 = 0x14,
	.dmi_data_2 = 0x18,
	.dmi_data_3 = 0x1c,
	.dmi_data_4 = 0x20,
	.dmi_data_5 = 0x24,
	.dmi_data_6 = 0x28,
	.dmi_data_7 = 0x2c,
	.dmi_data_8 = 0x30,
	.dmi_data_9 = 0x34,
	.dmi_data_10 = 0x38,
	.dmi_data_11 = 0x3c,
	.dmi_data_12 = 0x40,
	.dmi_data_13 = 0x44,
	.dmi_data_14 = 0x48,
	.dmi_data_15 = 0x4c,
	.dmi_cmd = 0x50,
	.dmi_status = 0x54,
	.dmi_lut_bank_cfg = 0x58,
	.module_lut_bank_cfg = 0x5c,
	.tpg_vc0_gain_cfg = 0x60,
	.tpg_ctrl = 0x64,
	.tpg_vc0_cfg0 = 0x68,
	.tpg_vc0_lfsr_seed = 0x6c,
	.tpg_vc0_hbi_cfg = 0x70,
	.tpg_vc0_vbi_cfg = 0x74,
	.tpg_vc0_color_bars_cfg = 0x78,
	.tpg_vc0_dt_0_cfg_0 = 0x7c,
	.tpg_vc0_dt_0_cfg_1 = 0x80,
	.tpg_vc0_dt_0_cfg_2 = 0x84,
	.tpg_vc0_dt_1_cfg_0 = 0x88,
	.tpg_vc0_dt_1_cfg_1 = 0x8c,
	.tpg_vc0_dt_1_cfg_2 = 0x90,
	.tpg_vc0_dt_2_cfg_0 = 0x94,
	.tpg_vc0_dt_2_cfg_1 = 0x98,
	.tpg_vc0_dt_2_cfg_2 = 0x9c,
	.tpg_vc0_dt_3_cfg_0 = 0xa0,
	.tpg_vc0_dt_3_cfg_1 = 0xa4,
	.tpg_vc0_dt_3_cfg_2 = 0xa8,
	.tpg_vc0_throttle = 0xac,
	.tpg_vc0_color_bar_cfa_color0 = 0xb0,
	.tpg_vc0_color_bar_cfa_color1 = 0xb4,
	.tpg_vc0_color_bar_cfa_color2 = 0xb8,
	.tpg_vc0_color_bar_cfa_color3 = 0xbc,
	.tpg_vc1_gain_cfg = 0xc0,
	.tpg_vc1_shdr_cfg = 0xc4,
	.tpg_vc1_cfg0 = 0xc8,
	.tpg_vc1_lfsr_seed = 0xcc,
	.tpg_vc1_hbi_cfg = 0xd0,
	.tpg_vc1_vbi_cfg = 0xd4,
	.tpg_vc1_color_bars_cfg = 0xd8,
	.tpg_vc1_dt_0_cfg_0 = 0xdc,
	.tpg_vc1_dt_0_cfg_1 = 0xe0,
	.tpg_vc1_dt_0_cfg_2 = 0xe4,
	.tpg_vc1_dt_1_cfg_0 = 0xe8,
	.tpg_vc1_dt_1_cfg_1 = 0xec,
	.tpg_vc1_dt_1_cfg_2 = 0xf0,
	.tpg_vc1_dt_2_cfg_0 = 0xf4,
	.tpg_vc1_dt_2_cfg_1 = 0xf8,
	.tpg_vc1_dt_2_cfg_2 = 0xfc,
	.tpg_vc1_dt_3_cfg_0 = 0x100,
	.tpg_vc1_dt_3_cfg_1 = 0x104,
	.tpg_vc1_dt_3_cfg_2 = 0x108,
	.tpg_vc1_throttle = 0x10c,
	.tpg_vc1_color_bar_cfa_color0 = 0x110,
	.tpg_vc1_color_bar_cfa_color1 = 0x114,
	.tpg_vc1_color_bar_cfa_color2 = 0x118,
	.tpg_vc1_color_bar_cfa_color3 = 0x11c,
	.tpg_vc2_gain_cfg = 0x120,
	.tpg_vc2_shdr_cfg = 0x124,
	.tpg_vc2_cfg0 = 0x128,
	.tpg_vc2_lfsr_seed = 0x12c,
	.tpg_vc2_hbi_cfg = 0x130,
	.tpg_vc2_vbi_cfg = 0x134,
	.tpg_vc2_color_bars_cfg = 0x138,
	.tpg_vc2_dt_0_cfg_0 = 0x13c,
	.tpg_vc2_dt_0_cfg_1 = 0x140,
	.tpg_vc2_dt_0_cfg_2 = 0x144,
	.tpg_vc2_dt_1_cfg_0 = 0x148,
	.tpg_vc2_dt_1_cfg_1 = 0x14c,
	.tpg_vc2_dt_1_cfg_2 = 0x150,
	.tpg_vc2_dt_2_cfg_0 = 0x154,
	.tpg_vc2_dt_2_cfg_1 = 0x158,
	.tpg_vc2_dt_2_cfg_2 = 0x15c,
	.tpg_vc2_dt_3_cfg_0 = 0x160,
	.tpg_vc2_dt_3_cfg_1 = 0x164,
	.tpg_vc2_dt_3_cfg_2 = 0x168,
	.tpg_vc2_throttle = 0x16c,
	.tpg_vc2_color_bar_cfa_color0 = 0x170,
	.tpg_vc2_color_bar_cfa_color1 = 0x174,
	.tpg_vc2_color_bar_cfa_color2 = 0x178,
	.tpg_vc2_color_bar_cfa_color3 = 0x17c,
	.tpg_vc3_gain_cfg = 0x180,
	.tpg_vc3_shdr_cfg = 0x184,
	.tpg_vc3_cfg0 = 0x188,
	.tpg_vc3_lfsr_seed = 0x18c,
	.tpg_vc3_hbi_cfg = 0x190,
	.tpg_vc3_vbi_cfg = 0x194,
	.tpg_vc3_color_bars_cfg = 0x198,
	.tpg_vc3_dt_0_cfg_0 = 0x19c,
	.tpg_vc3_dt_0_cfg_1 = 0x1a0,
	.tpg_vc3_dt_0_cfg_2 = 0x1a4,
	.tpg_vc3_dt_1_cfg_0 = 0x1a8,
	.tpg_vc3_dt_1_cfg_1 = 0x1ac,
	.tpg_vc3_dt_1_cfg_2 = 0x1b0,
	.tpg_vc3_dt_2_cfg_0 = 0x1b4,
	.tpg_vc3_dt_2_cfg_1 = 0x1b8,
	.tpg_vc3_dt_2_cfg_2 = 0x1bc,
	.tpg_vc3_dt_3_cfg_0 = 0x1c0,
	.tpg_vc3_dt_3_cfg_1 = 0x1c4,
	.tpg_vc3_dt_3_cfg_2 = 0x1c8,
	.tpg_vc3_throttle = 0x1cc,
	.tpg_vc3_color_bar_cfa_color0 = 0x1d0,
	.tpg_vc3_color_bar_cfa_color1 = 0x1d4,
	.tpg_vc3_color_bar_cfa_color2 = 0x1d8,
	.tpg_vc3_color_bar_cfa_color3 = 0x1dc,
	.top_irq_status = 0x1e0,
	.top_irq_mask = 0x1e4,
	.top_irq_clear = 0x1e8,
	.top_irq_set = 0x1ec,
	.irq_cmd = 0x1f0,
	.tpg_ctrl_cmd = 0x1f4,
	.test_bus_ctrl = 0x1f8,
	.spare = 0x1fc,

	/* Register fields below */
	.gen_shift = 0x1c,
	.rev_shift = 0x10,
	.step_shift = 0x0,
	.violation_shift = 0x0,
	.auto_load_pattern_shift = 0x15,
	.auto_load_en_shift = 0x14,
	.addr_shift = 0x0,
	.lut_sel_shift = 0x0,
	.data_shift = 0x0,
	.auto_load_status_clr_shift = 0x1,
	.auto_load_cmd_shift = 0x0,
	.auto_load_done_shift = 0x0,
	.bank_sel_shift = 0x0,
	.gain_shift = 0x0,
	.num_active_vc_shift = 0x1e,
	.overlap_shdr_en_shift = 0xa,
	.vc_dt_pattern_id_shift = 0x6,
	.num_active_lanes_shift = 0x4,
	.phy_sel_shift = 0x3,
	.num_frames_shift = 0x10,
	.num_batch_shift = 0xc,
	.num_active_dt_shift = 0x8,
	.fe_dis_shift = 0x7,
	.fs_dis_shift = 0x6,
	.vc_num_shift = 0x0,
	.seed_shift = 0x0,
	.hbi_clk_cnt_shift = 0x0,
	.vbi_line_cnt_shift = 0x0,
	.size_y_shift = 0x1c,
	.size_x_shift = 0x18,
	.xcfa_en_shift = 0x10,
	.rotate_period_shift = 0x8,
	.pix_intl_hdr_mode_shift = 0x6,
	.noise_en_shift = 0x5,
	.split_en_shift = 0x4,
	.qcfa_en_shift = 0x3,
	.pix_pattern_shift = 0x0,
	.frame_width_shift = 0x10,
	.frame_height_shift = 0x0,
	.crc_xor_mask_shift = 0x10,
	.ecc_xor_mask_shift = 0x8,
	.nfi_ssm_mode_en_shift = 0x7,
	.data_type_shift = 0x0,
	.encode_format_shift = 0x1c,
	.user_specified_payload_shift = 0x4,
	.payload_mode_shift = 0x0,
	.pattern_shift = 0x0,
	.array15_shift = 0x1e,
	.array14_shift = 0x1c,
	.array13_shift = 0x1a,
	.array12_shift = 0x18,
	.array11_shift = 0x16,
	.array10_shift = 0x14,
	.array9_shift = 0x12,
	.array8_shift = 0x10,
	.array7_shift = 0xe,
	.array6_shift = 0xc,
	.array5_shift = 0xa,
	.array4_shift = 0x8,
	.array3_shift = 0x6,
	.array2_shift = 0x4,
	.array1_shift = 0x2,
	.array0_shift = 0x0,
	.array31_shift = 0x1e,
	.array30_shift = 0x1c,
	.array29_shift = 0x1a,
	.array28_shift = 0x18,
	.array27_shift = 0x16,
	.array26_shift = 0x14,
	.array25_shift = 0x12,
	.array24_shift = 0x10,
	.array23_shift = 0xe,
	.array22_shift = 0xc,
	.array21_shift = 0xa,
	.array20_shift = 0x8,
	.array19_shift = 0x6,
	.array18_shift = 0x4,
	.array17_shift = 0x2,
	.array16_shift = 0x0,
	.array47_shift = 0x1e,
	.array46_shift = 0x1c,
	.array45_shift = 0x1a,
	.array44_shift = 0x18,
	.array43_shift = 0x16,
	.array42_shift = 0x14,
	.array41_shift = 0x12,
	.array40_shift = 0x10,
	.array39_shift = 0xe,
	.array38_shift = 0xc,
	.array37_shift = 0xa,
	.array36_shift = 0x8,
	.array35_shift = 0x6,
	.array34_shift = 0x4,
	.array33_shift = 0x2,
	.array32_shift = 0x0,
	.array63_shift = 0x1e,
	.array62_shift = 0x1c,
	.array61_shift = 0x1a,
	.array60_shift = 0x18,
	.array59_shift = 0x16,
	.array58_shift = 0x14,
	.array57_shift = 0x12,
	.array56_shift = 0x10,
	.array55_shift = 0xe,
	.array54_shift = 0xc,
	.array53_shift = 0xa,
	.array52_shift = 0x8,
	.array51_shift = 0x6,
	.array50_shift = 0x4,
	.array49_shift = 0x2,
	.array48_shift = 0x0,
	.shdr_offset_num_batch_shift = 0x10,
	.shdr_line_offset1_shift = 0x10,
	.shdr_line_offset0_shift = 0x0,
	.tpg_done_status_shift = 0x0,
	.rup_done_status_shift = 0x1,
	.status_vec_shift = 0x0,
	.rup_done_mask_vec_shift = 0x1,
	.tpg_done_mask_vec_shift = 0x0,
	.rup_done_clear_vec_shift = 0x1,
	.tpg_done_clear_vec_shift = 0x0,
	.set_vec_shift = 0x0,
	.set_shift = 0x4,
	.clear_shift = 0x0,
	.test_en_cmd_shift = 0x4,
	.hw_reset_shift = 0x0,
	.test_bus_en_shift = 0x0,
	.test_bus_sel_shift = 0x4,
	.spare_shift = 0x0,
	.async_mode_min_hbi = 0x0A,
	.async_mode_min_hbi_shift = 0x10,
	/* Custome Variables below */
};

#endif /* __TPG_HW_V_1_4_0_H__ */
