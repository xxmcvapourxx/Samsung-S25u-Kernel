// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <cam_sensor_cmn_header.h>
#include "cam_sensor_core.h"
#include "cam_sensor_util.h"
#include "cam_sensor_retention.h"
#if defined(CONFIG_USE_CAMERA_HW_BIG_DATA)
#include "cam_hw_bigdata.h"
#endif

#define S5KJN3_RETENTION_READY_ADDR 	0x19C4
#define S5KJN3_RETENTION_CHECKSUM_PASS	0x19C2
#define S5KJN3_RETENTION_STATUS_OK		0x0100


struct cam_sensor_i2c_reg_array s5kjn3_retention_init1_setting[] = {
	{ 0xFCFC,	0x4000, 0x00,	0x00 },
	{ 0x6012,	0x0001, 0x00,	0x00 },
};
struct cam_sensor_i2c_reg_array s5kjn3_retention_init2_setting[] = {
	{ 0x7002,	0x0008, 0x00,	0x00 },
	{ 0x7004,	0x12C0, 0x00,	0x00 },
	{ 0x70B8,	0x0D2C, 0x00,	0x00 },
	{ 0x6014,	0x0001, 0x00,	0x00 },
};
struct cam_sensor_i2c_reg_array s5kjn3_retention_init3_setting[] = {
	{ 0xFCFC,	0x2003, 0x00,	0x00 },
	{ 0x6208,	0xD1C2, 0x00,	0x00 },
	{ 0x620A,	0x1388, 0x00,	0x00 },
	{ 0x620C,	0xF6FF, 0x00,	0x00 },
	{ 0x620E,	0x1358, 0x00,	0x00 },
	{ 0x6210,	0x2800, 0x00,	0x00 },
	{ 0x6212,	0x1208, 0x00,	0x00 },
	{ 0x6214,	0x9307, 0x00,	0x00 },
	{ 0x6216,	0x0501, 0x00,	0x00 },
	{ 0x6218,	0x3E98, 0x00,	0x00 },
	{ 0x621A,	0x9C41, 0x00,	0x00 },
	{ 0x621C,	0x1441, 0x00,	0x00 },
	{ 0x621E,	0x638B, 0x00,	0x00 },
	{ 0x6220,	0xF600, 0x00,	0x00 },
	{ 0x6222,	0x8328, 0x00,	0x00 },
	{ 0x6224,	0x0600, 0x00,	0x00 },
	{ 0x6226,	0x33E7, 0x00,	0x00 },
	{ 0x6228,	0x1701, 0x00,	0x00 },
	{ 0x622A,	0x758F, 0x00,	0x00 },
	{ 0x622C,	0xB3F7, 0x00,	0x00 },
	{ 0x622E,	0x1701, 0x00,	0x00 },
	{ 0x6230,	0xD98F, 0x00,	0x00 },
	{ 0x6232,	0x1CC1, 0x00,	0x00 },
	{ 0x6234,	0xDC41, 0x00,	0x00 },
	{ 0x6236,	0x5441, 0x00,	0x00 },
	{ 0x6238,	0x638B, 0x00,	0x00 },
	{ 0x623A,	0xF600, 0x00,	0x00 },
	{ 0x623C,	0x8328, 0x00,	0x00 },
	{ 0x623E,	0x4600, 0x00,	0x00 },
	{ 0x6240,	0x33E7, 0x00,	0x00 },
	{ 0x6242,	0x1701, 0x00,	0x00 },
	{ 0x6244,	0x758F, 0x00,	0x00 },
	{ 0x6246,	0xB3F7, 0x00,	0x00 },
	{ 0x6248,	0x1701, 0x00,	0x00 },
	{ 0x624A,	0xD98F, 0x00,	0x00 },
	{ 0x624C,	0x5CC1, 0x00,	0x00 },
	{ 0x624E,	0x9C45, 0x00,	0x00 },
	{ 0x6250,	0x1445, 0x00,	0x00 },
	{ 0x6252,	0x638B, 0x00,	0x00 },
	{ 0x6254,	0xF600, 0x00,	0x00 },
	{ 0x6256,	0x8328, 0x00,	0x00 },
	{ 0x6258,	0x8600, 0x00,	0x00 },
	{ 0x625A,	0x33E7, 0x00,	0x00 },
	{ 0x625C,	0x1701, 0x00,	0x00 },
	{ 0x625E,	0x758F, 0x00,	0x00 },
	{ 0x6260,	0xB3F7, 0x00,	0x00 },
	{ 0x6262,	0x1701, 0x00,	0x00 },
	{ 0x6264,	0xD98F, 0x00,	0x00 },
	{ 0x6266,	0x1CC5, 0x00,	0x00 },
	{ 0x6268,	0xDC45, 0x00,	0x00 },
	{ 0x626A,	0x5445, 0x00,	0x00 },
	{ 0x626C,	0xC105, 0x00,	0x00 },
	{ 0x626E,	0x638B, 0x00,	0x00 },
	{ 0x6270,	0xF600, 0x00,	0x00 },
	{ 0x6272,	0x8328, 0x00,	0x00 },
	{ 0x6274,	0xC600, 0x00,	0x00 },
	{ 0x6276,	0x33E7, 0x00,	0x00 },
	{ 0x6278,	0x1701, 0x00,	0x00 },
	{ 0x627A,	0x758F, 0x00,	0x00 },
	{ 0x627C,	0xB3F7, 0x00,	0x00 },
	{ 0x627E,	0x1701, 0x00,	0x00 },
	{ 0x6280,	0xD98F, 0x00,	0x00 },
	{ 0x6282,	0x5CC5, 0x00,	0x00 },
	{ 0x6284,	0x4105, 0x00,	0x00 },
	{ 0x6286,	0x4106, 0x00,	0x00 },
	{ 0x6288,	0xE319, 0x00,	0x00 },
	{ 0x628A,	0x05F9, 0x00,	0x00 },
	{ 0x628C,	0x8280, 0x00,	0x00 },
	{ 0x628E,	0x0100, 0x00,	0x00 },
	{ 0x6290,	0x0111, 0x00,	0x00 },
	{ 0x6292,	0x06CE, 0x00,	0x00 },
	{ 0x6294,	0x22CC, 0x00,	0x00 },
	{ 0x6296,	0x26CA, 0x00,	0x00 },
	{ 0x6298,	0x4AC8, 0x00,	0x00 },
	{ 0x629A,	0x4EC6, 0x00,	0x00 },
	{ 0x629C,	0x97E0, 0x00,	0x00 },
	{ 0x629E,	0xFFFB, 0x00,	0x00 },
	{ 0x62A0,	0xE780, 0x00,	0x00 },
	{ 0x62A2,	0x0053, 0x00,	0x00 },
	{ 0x62A4,	0xB747, 0x00,	0x00 },
	{ 0x62A6,	0x0224, 0x00,	0x00 },
	{ 0x62A8,	0x83A7, 0x00,	0x00 },
	{ 0x62AA,	0x47B0, 0x00,	0x00 },
	{ 0x62AC,	0x238C, 0x00,	0x00 },
	{ 0x62AE,	0x01BC, 0x00,	0x00 },
	{ 0x62B0,	0xC1CF, 0x00,	0x00 },
	{ 0x62B2,	0x3764, 0x00,	0x00 },
	{ 0x62B4,	0x0324, 0x00,	0x00 },
	{ 0x62B6,	0x1304, 0x00,	0x00 },
	{ 0x62B8,	0x44E4, 0x00,	0x00 },
	{ 0x62BA,	0x0327, 0x00,	0x00 },
	{ 0x62BC,	0x0430, 0x00,	0x00 },
	{ 0x62BE,	0xB717, 0x00,	0x00 },
	{ 0x62C0,	0xFECA, 0x00,	0x00 },
	{ 0x62C2,	0x9387, 0x00,	0x00 },
	{ 0x62C4,	0x4723, 0x00,	0x00 },
	{ 0x62C6,	0x6306, 0x00,	0x00 },
	{ 0x62C8,	0xF700, 0x00,	0x00 },
	{ 0x62CA,	0x0327, 0x00,	0x00 },
	{ 0x62CC,	0x4430, 0x00,	0x00 },
	{ 0x62CE,	0x631D, 0x00,	0x00 },
	{ 0x62D0,	0xF706, 0x00,	0x00 },
	{ 0x62D2,	0x0545, 0x00,	0x00 },
	{ 0x62D4,	0x97A0, 0x00,	0x00 },
	{ 0x62D6,	0xFDFB, 0x00,	0x00 },
	{ 0x62D8,	0xE780, 0x00,	0x00 },
	{ 0x62DA,	0x004E, 0x00,	0x00 },
	{ 0x62DC,	0x9964, 0x00,	0x00 },
	{ 0x62DE,	0x0546, 0x00,	0x00 },
	{ 0x62E0,	0x9305, 0x00,	0x00 },
	{ 0x62E2,	0x0004, 0x00,	0x00 },
	{ 0x62E4,	0x1385, 0x00,	0x00 },
	{ 0x62E6,	0x4421, 0x00,	0x00 },
	{ 0x62E8,	0x97F0, 0x00,	0x00 },
	{ 0x62EA,	0xFFFB, 0x00,	0x00 },
	{ 0x62EC,	0xE780, 0x00,	0x00 },
	{ 0x62EE,	0x80BF, 0x00,	0x00 },
	{ 0x62F0,	0x0146, 0x00,	0x00 },
	{ 0x62F2,	0x9305, 0x00,	0x00 },
	{ 0x62F4,	0x0004, 0x00,	0x00 },
	{ 0x62F6,	0x1385, 0x00,	0x00 },
	{ 0x62F8,	0xA421, 0x00,	0x00 },
	{ 0x62FA,	0x97F0, 0x00,	0x00 },
	{ 0x62FC,	0xFFFB, 0x00,	0x00 },
	{ 0x62FE,	0xE780, 0x00,	0x00 },
	{ 0x6300,	0x60BE, 0x00,	0x00 },
	{ 0x6302,	0x8359, 0x00,	0x00 },
	{ 0x6304,	0x2400, 0x00,	0x00 },
	{ 0x6306,	0x6386, 0x00,	0x00 },
	{ 0x6308,	0x0902, 0x00,	0x00 },
	{ 0x630A,	0x3764, 0x00,	0x00 },
	{ 0x630C,	0x0324, 0x00,	0x00 },
	{ 0x630E,	0xB764, 0x00,	0x00 },
	{ 0x6310,	0x0324, 0x00,	0x00 },
	{ 0x6312,	0x1304, 0x00,	0x00 },
	{ 0x6314,	0x84E4, 0x00,	0x00 },
	{ 0x6316,	0x9384, 0x00,	0x00 },
	{ 0x6318,	0xC4EC, 0x00,	0x00 },
	{ 0x631A,	0x0149, 0x00,	0x00 },
	{ 0x631C,	0x9440, 0x00,	0x00 },
	{ 0x631E,	0x1044, 0x00,	0x00 },
	{ 0x6320,	0x4C40, 0x00,	0x00 },
	{ 0x6322,	0x0840, 0x00,	0x00 },
	{ 0x6324,	0x8982, 0x00,	0x00 },
	{ 0x6326,	0x0509, 0x00,	0x00 },
	{ 0x6328,	0xC535, 0x00,	0x00 },
	{ 0x632A,	0x3104, 0x00,	0x00 },
	{ 0x632C,	0x9104, 0x00,	0x00 },
	{ 0x632E,	0xE317, 0x00,	0x00 },
	{ 0x6330,	0x39FF, 0x00,	0x00 },
	{ 0x6332,	0x6244, 0x00,	0x00 },
	{ 0x6334,	0xF240, 0x00,	0x00 },
	{ 0x6336,	0xD244, 0x00,	0x00 },
	{ 0x6338,	0x4249, 0x00,	0x00 },
	{ 0x633A,	0xB249, 0x00,	0x00 },
	{ 0x633C,	0x0145, 0x00,	0x00 },
	{ 0x633E,	0x0561, 0x00,	0x00 },
	{ 0x6340,	0x17A3, 0x00,	0x00 },
	{ 0x6342,	0xFDFB, 0x00,	0x00 },
	{ 0x6344,	0x6700, 0x00,	0x00 },
	{ 0x6346,	0x4347, 0x00,	0x00 },
	{ 0x6348,	0xF240, 0x00,	0x00 },
	{ 0x634A,	0x6244, 0x00,	0x00 },
	{ 0x634C,	0xD244, 0x00,	0x00 },
	{ 0x634E,	0x4249, 0x00,	0x00 },
	{ 0x6350,	0xB249, 0x00,	0x00 },
	{ 0x6352,	0x0561, 0x00,	0x00 },
	{ 0x6354,	0x8280, 0x00,	0x00 },
	{ 0x6356,	0x0100, 0x00,	0x00 },
	{ 0xFCFC,	0x2001, 0x00,	0x00 },
	{ 0xA69C,	0x9062, 0x00,	0x00 },
	{ 0xA69E,	0x0324, 0x00,	0x00 },
	{ 0xFCFC,	0x2003, 0x00,	0x00 },
	{ 0x5E46,	0x0600, 0x00,	0x00 },
	{ 0x5E48,	0x00C0, 0x00,	0x00 },
	{ 0x5E4A,	0x0324, 0x00,	0x00 },
	{ 0x5E4C,	0x002C, 0x00,	0x00 },
	{ 0x5E4E,	0x002D, 0x00,	0x00 },
	{ 0x5E50,	0x0018, 0x00,	0x00 },
	{ 0x5E52,	0x092D, 0x00,	0x00 },
	{ 0x5ECC,	0x000C, 0x00,	0x00 },
	{ 0x5ECE,	0x0000, 0x00,	0x00 },
	{ 0x5E54,	0x0084, 0x00,	0x00 },
	{ 0x5E56,	0x0324, 0x00,	0x00 },
	{ 0x5E58,	0x0000, 0x00,	0x00 },
	{ 0x5E5A,	0x082D, 0x00,	0x00 },
	{ 0x5E5C,	0x0084, 0x00,	0x00 },
	{ 0x5E5E,	0x082D, 0x00,	0x00 },
	{ 0x5ED0,	0x003C, 0x00,	0x00 },
	{ 0x5ED2,	0x0000, 0x00,	0x00 },
	{ 0x5E60,	0x0000, 0x00,	0x00 },
	{ 0x5E62,	0x092D, 0x00,	0x00 },
	{ 0x5E64,	0x006C, 0x00,	0x00 },
	{ 0x5E66,	0x082D, 0x00,	0x00 },
	{ 0x5E68,	0x00C0, 0x00,	0x00 },
	{ 0x5E6A,	0x082D, 0x00,	0x00 },
	{ 0x5ED4,	0x0018, 0x00,	0x00 },
	{ 0x5ED6,	0x0000, 0x00,	0x00 },
	{ 0x5E6C,	0x00CC, 0x00,	0x00 },
	{ 0x5E6E,	0x0324, 0x00,	0x00 },
	{ 0x5E70,	0x0000, 0x00,	0x00 },
	{ 0x5E72,	0x002D, 0x00,	0x00 },
	{ 0x5E74,	0x0040, 0x00,	0x00 },
	{ 0x5E76,	0x082D, 0x00,	0x00 },
	{ 0x5ED8,	0x002A, 0x00,	0x00 },
	{ 0x5EDA,	0x0000, 0x00,	0x00 },
	{ 0x5E78,	0x00F6, 0x00,	0x00 },
	{ 0x5E7A,	0x0324, 0x00,	0x00 },
	{ 0x5E7C,	0x002A, 0x00,	0x00 },
	{ 0x5E7E,	0x002D, 0x00,	0x00 },
	{ 0x5E80,	0x006A, 0x00,	0x00 },
	{ 0x5E82,	0x082D, 0x00,	0x00 },
	{ 0x5EDC,	0x9001, 0x00,	0x00 },
	{ 0x5EDE,	0x0000, 0x00,	0x00 },
	{ 0x5E84,	0x045F, 0x00,	0x00 },
	{ 0x5E86,	0x0324, 0x00,	0x00 },
	{ 0x5E88,	0x0038, 0x00,	0x00 },
	{ 0x5E8A,	0x002D, 0x00,	0x00 },
	{ 0x5E8C,	0x0024, 0x00,	0x00 },
	{ 0x5E8E,	0x092D, 0x00,	0x00 },
	{ 0x5EE0,	0x2002, 0x00,	0x00 },
	{ 0x5EE2,	0x0000, 0x00,	0x00 },
	{ 0x5F00,	0x0403, 0x00,	0x00 },
	{ 0x5F00,	0x0403, 0x00,	0x00 },
	{ 0x5E44,	0x0001, 0x00,	0x00 },
	{ 0x5EF8,	0x8C50, 0x00,	0x00 },
	{ 0x5EFA,	0x0124, 0x00,	0x00 },
	{ 0x5EFC,	0x704D, 0x00,	0x00 },
	{ 0x5EFE,	0x0124, 0x00,	0x00 },
	{ 0x5F02,	0x0000, 0x00,	0x00 },
};
struct cam_sensor_i2c_reg_array s5kjn3_retention_init4_setting[] = {
	{ 0xFCFC,	0x4000, 0x00,	0x00 },
	{ 0x0136,	0x1300, 0x00,	0x00 },
	{ 0x013E,	0x00C8, 0x00,	0x00 },
	{ 0x0304,	0x0003, 0x00,	0x00 },
	{ 0x0306,	0x012C, 0x00,	0x00 },
	{ 0x030C,	0x0000, 0x00,	0x00 },
	{ 0x030E,	0x0003, 0x00,	0x00 },
	{ 0x0310,	0x010F, 0x00,	0x00 },
	{ 0x0312,	0x0000, 0x00,	0x00 },
	{ 0x031A,	0x0002, 0x00,	0x00 },
	{ 0x031C,	0x0036, 0x00,	0x00 },
	{ 0x031E,	0x0002, 0x00,	0x00 },
	{ 0xFCFC,	0x2000, 0x00,	0x00 },
	{ 0x206C,	0x00C0, 0x00,	0x00 },
	{ 0x206E,	0x0324, 0x00,	0x00 },
	{ 0x2068,	0x0100, 0x00,	0x00 },
	{ 0x1FF0,	0x0300, 0x00,	0x00 },
	{ 0xFCFC,	0x2001, 0x00,	0x00 },
	{ 0x8164,	0x0200, 0x00,	0x00 },
	{ 0x8162,	0x0103, 0x00,	0x00 },
	{ 0x8110,	0x0000, 0x00,	0x00 },
};
struct cam_sensor_i2c_reg_array s5kjn3_retention_init5_setting[] = {
	{ 0xFCFC,	0x4000, 0x00,	0x00 },
	{ 0x6214,	0xFFFF, 0x00,	0x00 },
	{ 0x6216,	0xFFFF, 0x00,	0x00 },
	{ 0x6218,	0xFFFF, 0x00,	0x00 },
	{ 0x621A,	0x0000, 0x00,	0x00 },
	{ 0x621C,	0x0000, 0x00,	0x00 },
	{ 0x6220,	0x0000, 0x00,	0x00 },
	{ 0x623C,	0x0000, 0x00,	0x00 },
	{ 0x6006,	0x0600, 0x00,	0x00 },
	{ 0x0108,	0x0300, 0x00,	0x00 },
};

struct cam_sensor_i2c_reg_setting s5kjn3_retention_init_settings[] =  {
	{	s5kjn3_retention_init1_setting,
		ARRAY_SIZE(s5kjn3_retention_init1_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		1
	},
	{	s5kjn3_retention_init2_setting,
		ARRAY_SIZE(s5kjn3_retention_init2_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		1
	},
	{	s5kjn3_retention_init3_setting,
		ARRAY_SIZE(s5kjn3_retention_init3_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		1
	},
	{	s5kjn3_retention_init4_setting,
		ARRAY_SIZE(s5kjn3_retention_init4_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		6
	},
	{	s5kjn3_retention_init5_setting,
		ARRAY_SIZE(s5kjn3_retention_init5_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		3
	},
};


struct cam_sensor_i2c_reg_array s5kjn3_stream_on_setting[] = {
	{ 0x0100,	0x0100, 0x00,	0x00 },
};

struct cam_sensor_i2c_reg_setting s5kjn3_stream_on_settings[] =  {
	{	s5kjn3_stream_on_setting,
		ARRAY_SIZE(s5kjn3_stream_on_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		0
	},
};

struct cam_sensor_i2c_reg_array s5kjn3_retention_enable_setting[] = {
	{ 0xFCFC,	0x2003, 0x00,	0x00 },
	{ 0x5E44,	0x0101, 0x00,	0x00 },
	{ 0xFCFC,	0x4000, 0x00,	0x00 },
};


struct cam_sensor_i2c_reg_array s5kjn3_stream_off_setting[] = {
	{ 0x0100,	0x0000, 0x00,	0x00 },
};

struct cam_sensor_i2c_reg_setting s5kjn3_stream_off_settings[] =  {
	{	s5kjn3_retention_enable_setting,
		ARRAY_SIZE(s5kjn3_retention_enable_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		0
	},
	{	s5kjn3_stream_off_setting,
		ARRAY_SIZE(s5kjn3_stream_off_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		0
	},

};


struct cam_sensor_i2c_reg_array s5kjn3_retention_page_setting[] = {
	{ 0xFCFC,	0x4000, 0x00,	0x00 },
};

struct cam_sensor_i2c_reg_setting s5kjn3_retention_page_settings[] = {
	{	s5kjn3_retention_page_setting,
		ARRAY_SIZE(s5kjn3_retention_page_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		0
	},
};

struct cam_sensor_i2c_reg_array s5kjn3_normal_page_setting[] = {
	{ 0xFCFC,	0x4000, 0x00,	0x00 },
};

struct cam_sensor_i2c_reg_setting s5kjn3_normal_page_settings[] = {
	{	s5kjn3_normal_page_setting,
		ARRAY_SIZE(s5kjn3_normal_page_setting),
		CAMERA_SENSOR_I2C_TYPE_WORD,
		CAMERA_SENSOR_I2C_TYPE_WORD,
		0
	},
};

int s5kjn3_stream_on(struct cam_sensor_ctrl_t *s_ctrl) {
	int rc = 0;

	CAM_INFO(CAM_SENSOR, "[RET_DBG] stream on");
	rc = cam_sensor_write_settings(&s_ctrl->io_master_info,
		s5kjn3_stream_on_settings, ARRAY_SIZE(s5kjn3_stream_on_settings));
	if (rc < 0) {
		CAM_ERR(CAM_SENSOR,
			"[RET_DBG] Failed to write stream on rc = %d", rc);
		return rc;
	}

#if defined(CONFIG_CAMERA_FRAME_CNT_CHECK)
	rc = cam_sensor_wait_stream_onoff(s_ctrl, true);
#endif

	return rc;
}

int s5kjn3_stream_off(struct cam_sensor_ctrl_t *s_ctrl) {
	int rc = 0;

	CAM_INFO(CAM_SENSOR, "[RET_DBG] stream off");
	rc = cam_sensor_write_settings(&s_ctrl->io_master_info,
		s5kjn3_stream_off_settings, ARRAY_SIZE(s5kjn3_stream_off_settings));
	if (rc < 0) {
		CAM_ERR(CAM_SENSOR,
			"[RET_DBG] Failed to write stream off rc = %d", rc);
		return rc;
	}

#if defined(CONFIG_CAMERA_FRAME_CNT_CHECK)
	rc = cam_sensor_wait_stream_onoff(s_ctrl, false);
#endif

	return rc;
}

int s5kjn3_retention_wait_ready(struct cam_sensor_ctrl_t *s_ctrl)
{
	int rc = 0;

	if (s_ctrl->streamon_count == 0 ||
		s_ctrl->retention_stream_on == false) {
		rc = s5kjn3_stream_on(s_ctrl);
		rc |= s5kjn3_stream_off(s_ctrl);
	}


	rc = cam_sensor_write_settings(&s_ctrl->io_master_info,
		s5kjn3_retention_page_settings, ARRAY_SIZE(s5kjn3_retention_page_settings));
	rc |= camera_io_dev_poll(&s_ctrl->io_master_info,
		S5KJN3_RETENTION_READY_ADDR, S5KJN3_RETENTION_STATUS_OK, 0,
		CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_WORD,
		100);
	rc |= cam_sensor_write_settings(&s_ctrl->io_master_info,
		s5kjn3_normal_page_settings, ARRAY_SIZE(s5kjn3_normal_page_settings));

	return rc;
}

int s5kjn3_retention_checksum(struct cam_sensor_ctrl_t *s_ctrl)
{
	int rc = 0;

	rc = cam_sensor_write_settings(&s_ctrl->io_master_info,
			s5kjn3_retention_init_settings, ARRAY_SIZE(s5kjn3_retention_init_settings));

	usleep_range(3000, 4000);
	
	rc = cam_sensor_write_settings(&s_ctrl->io_master_info,
		s5kjn3_retention_page_settings, ARRAY_SIZE(s5kjn3_retention_page_settings));
	rc |= camera_io_dev_poll(&s_ctrl->io_master_info,
		S5KJN3_RETENTION_CHECKSUM_PASS, S5KJN3_RETENTION_STATUS_OK, 0,
		CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_WORD,
		100);
	rc |= cam_sensor_write_settings(&s_ctrl->io_master_info,
		s5kjn3_normal_page_settings, ARRAY_SIZE(s5kjn3_normal_page_settings));

	return rc;
}

int s5kjn3_retention_init(struct cam_sensor_ctrl_t *s_ctrl)
{
	int32_t rc = 0;

	CAM_INFO(CAM_SENSOR, "[RET_DBG] E");

	if (s_ctrl->i2c_data.init_settings.is_settings_valid &&
		(s_ctrl->i2c_data.init_settings.request_id == 0)) {
		rc = cam_sensor_apply_settings(s_ctrl, 0,
			CAM_SENSOR_PACKET_OPCODE_SENSOR_INITIAL_CONFIG);
		if (rc < 0) {
			CAM_ERR(CAM_SENSOR,
				"[RET_DBG] Failed to write init rc = %d", rc);
#if defined(CONFIG_USE_CAMERA_HW_BIG_DATA)
			hw_bigdata_i2c_from_sensor(s_ctrl);
#endif
			goto end;
		}

		rc |= s5kjn3_retention_wait_ready(s_ctrl);
		if (rc != 0) {
			CAM_ERR(CAM_SENSOR,
				"[RET_DBG] Failed to wait retention ready rc = %d", rc);
			goto end;
		}
	}
end:
	s_ctrl->retention_stream_on = false;

	CAM_INFO(CAM_SENSOR, "[RET_DBG] X");

	return rc;
}

int s5kjn3_retention_exit(struct cam_sensor_ctrl_t *s_ctrl)
{
	int32_t rc = 0;

	CAM_INFO(CAM_SENSOR, "[RET_DBG] E");

	s_ctrl->retention_checksum = false;

	rc |= s5kjn3_retention_checksum(s_ctrl);
	if (rc != 0)
		CAM_ERR(CAM_SENSOR,	"[RET_DBG] Retention checksum fail, rc = %d", rc);

	if (rc == 0)
		s_ctrl->retention_checksum = true;

	s_ctrl->retention_stream_on = false;

	CAM_INFO(CAM_SENSOR, "[RET_DBG] X");

	return rc;
}

// Pre-Stream off, Retention/Checksum register reset
int s5kjn3_retention_enter(struct cam_sensor_ctrl_t *s_ctrl)
{
	int32_t rc = 0;

	CAM_INFO(CAM_SENSOR, "[RET_DBG] E");

	rc = s5kjn3_retention_wait_ready(s_ctrl);
	if (rc < 0)
		CAM_ERR(CAM_SENSOR, "[RET_DBG] Failed to enter retention mode rc = %d", rc);

	CAM_INFO(CAM_SENSOR, "[RET_DBG] X");

	return rc;
}

struct cam_sensor_retention_info s5kjn3_retention_info = {
	.retention_init = s5kjn3_retention_init,
	.retention_exit = s5kjn3_retention_exit,
	.retention_enter = s5kjn3_retention_enter,
	.retention_support = true,
};
