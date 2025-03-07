/*
 * Copyright (c) 2019-2020 The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ANDROID_HARDWARE_POWER_POWER_H
#define ANDROID_HARDWARE_POWER_POWER_H

#include <aidl/android/hardware/power/BnPower.h>
#include "aidl/android/hardware/power/SessionTag.h"
#include "power-common.h"

namespace aidl {
namespace android {
namespace hardware {
namespace power {
namespace impl {

class Power : public BnPower {
    public:
        Power() : BnPower(){
            power_init();
        }
        ndk::ScopedAStatus setMode(Mode type, bool enabled) override;
        ndk::ScopedAStatus isModeSupported(Mode type, bool* _aidl_return) override;
        ndk::ScopedAStatus setBoost(Boost type, int32_t durationMs) override;
        ndk::ScopedAStatus isBoostSupported(Boost type, bool* _aidl_return) override;
        ndk::ScopedAStatus createHintSession(int32_t tgid, int32_t uid,
                                             const std::vector<int32_t>& threadIds,
                                             int64_t durationNanos,
                                             std::shared_ptr<IPowerHintSession>* _aidl_return) override;
		ndk::ScopedAStatus createHintSessionWithConfig(
            int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds, int64_t durationNanos,
            SessionTag tag, SessionConfig* config,
            std::shared_ptr<IPowerHintSession>* _aidl_return) override;
		ndk::ScopedAStatus getHintSessionPreferredRate(int64_t* outNanoseconds) override;
		ndk::ScopedAStatus getSessionChannel(int32_t tgid, int32_t uid,
                                         ChannelConfig* _aidl_return) override;
		ndk::ScopedAStatus closeSessionChannel(int32_t tgid, int32_t uid) override;
};

}  // namespace impl
}  // namespace power
}  // namespace hardware
}  // namespace android
}  // namespace aidl
#endif  // ANDROID_HARDWARE_POWER_POWER_H
