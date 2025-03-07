/*
 * This file was generated by the CommonAPI Generators.
 * Used org.genivi.commonapi.someip 3.2.0.v202012010944.
 * Used org.franca.core 0.13.1.201807231814.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */
#include <v0/com/qualcomm/qti/location/LocIdlAPISomeIPStubAdapter.hpp>
#include <v0/com/qualcomm/qti/location/LocIdlAPI.hpp>

#if !defined (COMMONAPI_INTERNAL_COMPILATION)
#define COMMONAPI_INTERNAL_COMPILATION
#define HAS_DEFINED_COMMONAPI_INTERNAL_COMPILATION_HERE
#endif

#include <CommonAPI/SomeIP/AddressTranslator.hpp>

#if defined (HAS_DEFINED_COMMONAPI_INTERNAL_COMPILATION_HERE)
#undef COMMONAPI_INTERNAL_COMPILATION
#undef HAS_DEFINED_COMMONAPI_INTERNAL_COMPILATION_HERE
#endif

namespace v0 {
namespace com {
namespace qualcomm {
namespace qti {
namespace location {

std::shared_ptr<CommonAPI::SomeIP::StubAdapter> createLocIdlAPISomeIPStubAdapter(
                   const CommonAPI::SomeIP::Address &_address,
                   const std::shared_ptr<CommonAPI::SomeIP::ProxyConnection> &_connection,
                   const std::shared_ptr<CommonAPI::StubBase> &_stub) {
    return std::make_shared< LocIdlAPISomeIPStubAdapter<::v0::com::qualcomm::qti::location::LocIdlAPIStub>>(_address, _connection, _stub);
}

void initializeLocIdlAPISomeIPStubAdapter() {
    CommonAPI::SomeIP::AddressTranslator::get()->insert(
        "local:com.qualcomm.qti.location.LocIdlAPI:v0_2:com.qualcomm.qti.location.LocIdlAPI",
         0xee00, 0x1, 0, 2);
    CommonAPI::SomeIP::Factory::get()->registerStubAdapterCreateMethod(
        "com.qualcomm.qti.location.LocIdlAPI:v0_2",
        &createLocIdlAPISomeIPStubAdapter);
}

INITIALIZER(registerLocIdlAPISomeIPStubAdapter) {
    CommonAPI::SomeIP::Factory::get()->registerInterface(initializeLocIdlAPISomeIPStubAdapter);
}

} // namespace location
} // namespace qti
} // namespace qualcomm
} // namespace com
} // namespace v0
