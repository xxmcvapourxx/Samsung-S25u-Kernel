/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

package vendor.qti.hardware.display.color;

@VintfStability
parcelable PAConfigData {
    int hue;
    float saturation;
    float value;
    float contrast;
    float sat_thresh;
}
