#include "diameter_dictionary.hpp"
#include "diameter_types.hpp"
#include "ddos_samurai/core/json.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>
#include <sstream>

namespace ddos_samurai::telecom::diameter {

DecodedAvp DecodedAvp::CreateString(uint32_t code, const std::string& str, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::UTF8_STRING;
    a.str_val = str;
    return a;
}

DecodedAvp DecodedAvp::CreateU32(uint32_t code, uint32_t val, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::UNSIGNED32;
    a.u32_val = val;
    return a;
}

DecodedAvp DecodedAvp::CreateU64(uint32_t code, uint64_t val, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::UNSIGNED64;
    a.u64_val = val;
    return a;
}

DecodedAvp DecodedAvp::CreateI32(uint32_t code, int32_t val, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::INTEGER32;
    a.i32_val = val;
    return a;
}

DecodedAvp DecodedAvp::CreateI64(uint32_t code, int64_t val, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::INTEGER64;
    a.i64_val = val;
    return a;
}

DecodedAvp DecodedAvp::CreateFloat32(uint32_t code, float val, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::FLOAT32;
    a.f32_val = val;
    return a;
}

DecodedAvp DecodedAvp::CreateFloat64(uint32_t code, double val, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::FLOAT64;
    a.f64_val = val;
    return a;
}

DecodedAvp DecodedAvp::CreateAddressIpv4(uint32_t code, uint32_t ip, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::ADDRESS;
    a.ipv4_val = ip;
    return a;
}

DecodedAvp DecodedAvp::CreateTime(uint32_t code, uint32_t ntp_secs, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::TIME;
    a.time_val = ntp_secs;
    return a;
}

DecodedAvp DecodedAvp::CreateOctetString(uint32_t code, const std::vector<uint8_t>& octets, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::OCTET_STRING;
    a.octet_string_val = octets;
    return a;
}

DecodedAvp DecodedAvp::CreateGrouped(uint32_t code, std::vector<DecodedAvp> children, uint8_t flags, uint32_t vendor_id) {
    DecodedAvp a;
    a.code = code;
    a.vendor_id = vendor_id;
    a.flags = flags;
    a.type = AvpDataType::GROUPED;
    a.grouped_val = std::move(children);
    return a;
}

DiameterDictionary::DiameterDictionary() {
    LoadBuiltinCarrierDictionary();
}

void DiameterDictionary::AddAvpDefinition(const AvpDefinition& def) {
    uint64_t key = MakeAvpKey(def.code, def.vendor_id);
    avp_by_key_[key] = def;
    if (!def.name.empty()) {
        avp_by_name_[def.name] = key;
    }
}

void DiameterDictionary::AddCommandDefinition(const CommandDefinition& def) {
    uint64_t key = MakeCommandKey(def.code, def.app_id, def.is_request);
    commands_[key] = def;
    if (!def.name.empty()) {
        std::string name_key = def.name + (def.is_request ? ":req" : ":ans");
        commands_by_name_[name_key] = key;
    }
}

const AvpDefinition* DiameterDictionary::FindAvp(uint32_t code, uint32_t vendor_id) const noexcept {
    auto it = avp_by_key_.find(MakeAvpKey(code, vendor_id));
    if (it != avp_by_key_.end()) {
        return &it->second;
    }
    // Fallback if vendor_id is given but definition is standard (vendor 0)
    if (vendor_id != 0) {
        auto it0 = avp_by_key_.find(MakeAvpKey(code, 0));
        if (it0 != avp_by_key_.end()) {
            return &it0->second;
        }
    }
    return nullptr;
}

const AvpDefinition* DiameterDictionary::FindAvpByName(const std::string& name) const noexcept {
    auto it = avp_by_name_.find(name);
    if (it != avp_by_name_.end()) {
        auto it_def = avp_by_key_.find(it->second);
        if (it_def != avp_by_key_.end()) {
            return &it_def->second;
        }
    }
    return nullptr;
}

const CommandDefinition* DiameterDictionary::FindCommand(uint32_t code, uint32_t app_id, bool is_request) const noexcept {
    auto it = commands_.find(MakeCommandKey(code, app_id, is_request));
    if (it != commands_.end()) {
        return &it->second;
    }
    // Fallback to app_id 0 if applicable
    if (app_id != 0) {
        auto it0 = commands_.find(MakeCommandKey(code, 0, is_request));
        if (it0 != commands_.end()) {
            return &it0->second;
        }
    }
    return nullptr;
}

const CommandDefinition* DiameterDictionary::FindCommandByName(const std::string& name, bool is_request) const noexcept {
    std::string name_key = name + (is_request ? ":req" : ":ans");
    auto it = commands_by_name_.find(name_key);
    if (it != commands_by_name_.end()) {
        auto it_def = commands_.find(it->second);
        if (it_def != commands_.end()) {
            return &it_def->second;
        }
    }
    return nullptr;
}

void DiameterDictionary::Clear() {
    avp_by_key_.clear();
    avp_by_name_.clear();
    commands_.clear();
    commands_by_name_.clear();
}

void DiameterDictionary::LoadBuiltinCarrierDictionary() {
    // 1. RFC 6733 Base AVPs
    AddAvpDefinition({263, 0, "Session-Id", AvpDataType::UTF8_STRING, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({264, 0, "Origin-Host", AvpDataType::UTF8_STRING, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({296, 0, "Origin-Realm", AvpDataType::UTF8_STRING, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({283, 0, "Destination-Realm", AvpDataType::UTF8_STRING, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({293, 0, "Destination-Host", AvpDataType::UTF8_STRING, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({268, 0, "Result-Code", AvpDataType::UNSIGNED32, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({258, 0, "Auth-Application-Id", AvpDataType::UNSIGNED32, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({295, 0, "Termination-Cause", AvpDataType::UNSIGNED32, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({257, 0, "Host-IP-Address", AvpDataType::ADDRESS, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({266, 0, "Vendor-Id", AvpDataType::UNSIGNED32, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({269, 0, "Product-Name", AvpDataType::UTF8_STRING, 0, {}});
    AddAvpDefinition({273, 0, "Disconnect-Cause", AvpDataType::UNSIGNED32, AVP_FLAG_MANDATORY, {}});

    // 2. 3GPP Ro / Gx / Gy AVPs
    AddAvpDefinition({416, 0, "CC-Request-Type", AvpDataType::UNSIGNED32, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({415, 0, "CC-Request-Number", AvpDataType::UNSIGNED32, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({461, 0, "Service-Context-Id", AvpDataType::UTF8_STRING, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({450, 0, "Subscription-Id-Type", AvpDataType::UNSIGNED32, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({444, 0, "Subscription-Id-Data", AvpDataType::UTF8_STRING, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({421, 0, "CC-Total-Octets", AvpDataType::UNSIGNED64, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({8,   0, "Framed-IP-Address", AvpDataType::ADDRESS, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition({432, 10415, "Rating-Group", AvpDataType::UNSIGNED32, static_cast<uint8_t>(AVP_FLAG_MANDATORY | AVP_FLAG_VENDOR), {}});
    AddAvpDefinition({1032, 10415, "3GPP-RAT-Type", AvpDataType::OCTET_STRING, static_cast<uint8_t>(AVP_FLAG_MANDATORY | AVP_FLAG_VENDOR), {}});

    // Grouped AVPs
    AvpDefinition used_service_unit{446, 0, "Used-Service-Unit", AvpDataType::GROUPED, AVP_FLAG_MANDATORY, {}};
    used_service_unit.children.push_back({421, 0, "CC-Total-Octets", AvpDataType::UNSIGNED64, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition(used_service_unit);

    AvpDefinition mscc{456, 0, "Multiple-Services-Credit-Control", AvpDataType::GROUPED, AVP_FLAG_MANDATORY, {}};
    mscc.children.push_back({432, 10415, "Rating-Group", AvpDataType::UNSIGNED32, static_cast<uint8_t>(AVP_FLAG_MANDATORY | AVP_FLAG_VENDOR), {}});
    mscc.children.push_back(used_service_unit);
    AddAvpDefinition(mscc);

    AvpDefinition sub_id{443, 0, "Subscription-Id", AvpDataType::GROUPED, AVP_FLAG_MANDATORY, {}};
    sub_id.children.push_back({450, 0, "Subscription-Id-Type", AvpDataType::UNSIGNED32, AVP_FLAG_MANDATORY, {}});
    sub_id.children.push_back({444, 0, "Subscription-Id-Data", AvpDataType::UTF8_STRING, AVP_FLAG_MANDATORY, {}});
    AddAvpDefinition(sub_id);

    // Commands
    AddCommandDefinition({257, 0, "Capabilities-Exchange-Request", true, {264, 296, 257, 266, 269}, {258}});
    AddCommandDefinition({257, 0, "Capabilities-Exchange-Answer", false, {268, 264, 296}, {257, 266, 269}});
    AddCommandDefinition({280, 0, "Device-Watchdog-Request", true, {264, 296}, {}});
    AddCommandDefinition({280, 0, "Device-Watchdog-Answer", false, {268, 264, 296}, {}});
    AddCommandDefinition({282, 0, "Disconnect-Peer-Request", true, {264, 296, 273}, {}});
    AddCommandDefinition({282, 0, "Disconnect-Peer-Answer", false, {268, 264, 296}, {}});

    // CCR / CCA (Ro RFC 4006 - app_id 4)
    AddCommandDefinition({272, 4, "Credit-Control-Request", true,
                         {263, 264, 296, 283, 258, 461, 416, 415},
                         {293, 443, 456, 8}});
    AddCommandDefinition({272, 4, "Credit-Control-Answer", false,
                         {263, 268, 264, 296, 416, 415},
                         {456}});

    // CCR / CCA (Gx 3GPP TS 29.212 - app_id 16777216)
    AddCommandDefinition({272, 16777216, "Credit-Control-Request", true,
                         {263, 264, 296, 283, 258, 416, 415},
                         {293, 443, 456, 8, 1032}});
    AddCommandDefinition({272, 16777216, "Credit-Control-Answer", false,
                         {263, 268, 264, 296, 416, 415},
                         {456}});
}

bool DiameterDictionary::LoadFromJson(const std::string& /*json_str*/, std::string* /*error_msg*/) {
    return false;
}

bool DiameterDictionary::EncodeAvp(const DecodedAvp& /*avp*/, std::vector<uint8_t>& /*out_buf*/) const {
    return false;
}

bool DiameterDictionary::DecodeAvp(const uint8_t* /*data*/, size_t /*len*/, DecodedAvp& /*out_avp*/, size_t& /*bytes_consumed*/) const {
    return false;
}

bool DiameterDictionary::DecodeAvps(const uint8_t* /*data*/, size_t /*len*/, std::vector<DecodedAvp>& /*out_avps*/) const {
    return false;
}

bool DiameterDictionary::ValidateAvp(const DecodedAvp& /*avp*/, std::string& /*err*/) const {
    return true;
}

bool DiameterDictionary::ValidateMessage(uint32_t /*cmd_code*/, uint32_t /*app_id*/, bool /*is_request*/,
                                         const std::vector<DecodedAvp>& /*avps*/, std::string& /*err*/) const {
    return true;
}

} // namespace ddos_samurai::telecom::diameter
