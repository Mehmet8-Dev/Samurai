#include "diameter_dictionary.hpp"
#include "diameter_types.hpp"
#include "ddos_samurai/core/json.hpp"

#include <arpa/inet.h>
#include <endian.h>
#include <cstring>
#include <algorithm>
#include <sstream>

namespace ddos_samurai::telecom::diameter {

namespace {

AvpDataType StringToAvpDataType(const std::string& type_str) {
    if (type_str == "OCTET_STRING") return AvpDataType::OCTET_STRING;
    if (type_str == "INTEGER32") return AvpDataType::INTEGER32;
    if (type_str == "INTEGER64") return AvpDataType::INTEGER64;
    if (type_str == "UNSIGNED32") return AvpDataType::UNSIGNED32;
    if (type_str == "UNSIGNED64") return AvpDataType::UNSIGNED64;
    if (type_str == "FLOAT32") return AvpDataType::FLOAT32;
    if (type_str == "FLOAT64") return AvpDataType::FLOAT64;
    if (type_str == "ADDRESS") return AvpDataType::ADDRESS;
    if (type_str == "TIME") return AvpDataType::TIME;
    if (type_str == "UTF8_STRING") return AvpDataType::UTF8_STRING;
    if (type_str == "GROUPED") return AvpDataType::GROUPED;
    return AvpDataType::OCTET_STRING;
}

uint8_t ParseFlags(const samurai::core::json::Value* flag_val, uint32_t vendor_id) {
    uint8_t flags = 0;
    if (vendor_id != 0) {
        flags |= AVP_FLAG_VENDOR;
    }
    if (!flag_val) return flags;
    if (flag_val->is_number()) {
        flags |= static_cast<uint8_t>(flag_val->as_int());
    } else if (flag_val->is_string()) {
        std::string s = flag_val->as_string();
        for (char c : s) {
            if (c == 'M' || c == 'm') flags |= AVP_FLAG_MANDATORY;
            if (c == 'V' || c == 'v') flags |= AVP_FLAG_VENDOR;
            if (c == 'P' || c == 'p') flags |= AVP_FLAG_PROTECTED;
        }
    }
    return flags;
}

bool ParseAvpDefinition(const samurai::core::json::Value& v, AvpDefinition& def) {
    if (!v.is_object()) return false;
    const auto* code_val = v.find("code");
    if (!code_val) return false;
    def.code = static_cast<uint32_t>(code_val->as_int());

    const auto* vendor_val = v.find("vendor_id");
    def.vendor_id = vendor_val ? static_cast<uint32_t>(vendor_val->as_int()) : 0;

    const auto* name_val = v.find("name");
    def.name = name_val ? name_val->as_string() : "";

    const auto* type_val = v.find("type");
    std::string type_str = type_val ? type_val->as_string() : "OCTET_STRING";
    def.type = StringToAvpDataType(type_str);

    def.flags = ParseFlags(v.find("flags"), def.vendor_id);

    const auto* children_val = v.find("children");
    if (children_val && children_val->is_array()) {
        for (const auto& child_elem : children_val->elements()) {
            AvpDefinition child_def;
            if (ParseAvpDefinition(child_elem, child_def)) {
                def.children.push_back(std::move(child_def));
            }
        }
    }
    return true;
}

bool ParseCommandDefinition(const samurai::core::json::Value& v, CommandDefinition& cmd) {
    if (!v.is_object()) return false;
    const auto* code_val = v.find("code");
    if (!code_val) return false;
    cmd.code = static_cast<uint32_t>(code_val->as_int());

    const auto* app_val = v.find("app_id");
    cmd.app_id = app_val ? static_cast<uint32_t>(app_val->as_int()) : 0;

    const auto* name_val = v.find("name");
    cmd.name = name_val ? name_val->as_string() : "";

    const auto* req_val = v.find("is_request");
    cmd.is_request = req_val ? req_val->as_bool(true) : true;

    const auto* req_avps = v.find("required_avps");
    if (req_avps && req_avps->is_array()) {
        for (const auto& elem : req_avps->elements()) {
            cmd.required_avps.push_back(static_cast<uint32_t>(elem.as_int()));
        }
    }

    const auto* opt_avps = v.find("optional_avps");
    if (opt_avps && opt_avps->is_array()) {
        for (const auto& elem : opt_avps->elements()) {
            cmd.optional_avps.push_back(static_cast<uint32_t>(elem.as_int()));
        }
    }
    return true;
}

} // namespace

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
    if (def.vendor_id == 0 && def.code < FAST_LOOKUP_TABLE_SIZE) {
        fast_table_[def.code] = def;
        fast_defined_[def.code] = true;
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

const AvpDefinition* DiameterDictionary::FindAvpSlow(uint32_t code, uint32_t vendor_id) const noexcept {
    auto it = avp_by_key_.find(MakeAvpKey(code, vendor_id));
    if (it != avp_by_key_.end()) {
        return &it->second;
    }
    // Fallback if vendor_id is given but definition is standard (vendor 0)
    if (vendor_id != 0) {
        if (code < FAST_LOOKUP_TABLE_SIZE && fast_defined_[code]) {
            return &fast_table_[code];
        }
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
    fast_defined_.fill(false);
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

bool DiameterDictionary::LoadFromJson(const std::string& json_str, std::string* error_msg) {
    auto parse_res = samurai::core::json::Parse(json_str);
    if (!parse_res.ok) {
        if (error_msg) *error_msg = "JSON parse error: " + parse_res.error;
        return false;
    }

    const auto& root = parse_res.value;
    if (!root.is_object()) {
        if (error_msg) *error_msg = "Root JSON must be an object";
        return false;
    }

    const auto* avps = root.find("avps");
    if (avps && avps->is_array()) {
        for (const auto& elem : avps->elements()) {
            AvpDefinition def;
            if (ParseAvpDefinition(elem, def)) {
                AddAvpDefinition(def);
            }
        }
    }

    const auto* cmds = root.find("commands");
    if (cmds && cmds->is_array()) {
        for (const auto& elem : cmds->elements()) {
            CommandDefinition cmd;
            if (ParseCommandDefinition(elem, cmd)) {
                AddCommandDefinition(cmd);
            }
        }
    }

    return true;
}

bool DiameterDictionary::EncodeAvp(const DecodedAvp& avp, std::vector<uint8_t>& out_buf) const {
    bool has_vendor = (avp.flags & AVP_FLAG_VENDOR) != 0 || avp.vendor_id != 0;
    uint8_t flags = avp.flags;
    if (has_vendor) {
        flags |= AVP_FLAG_VENDOR;
    }

    size_t header_len = has_vendor ? 12 : 8;
    std::vector<uint8_t> payload;

    switch (avp.type) {
        case AvpDataType::OCTET_STRING:
            payload = avp.octet_string_val;
            break;
        case AvpDataType::UTF8_STRING:
            payload.assign(avp.str_val.begin(), avp.str_val.end());
            break;
        case AvpDataType::INTEGER32: {
            uint32_t val_be = htonl(static_cast<uint32_t>(avp.i32_val));
            payload.resize(4);
            std::memcpy(payload.data(), &val_be, 4);
            break;
        }
        case AvpDataType::UNSIGNED32: {
            uint32_t val_be = htonl(avp.u32_val);
            payload.resize(4);
            std::memcpy(payload.data(), &val_be, 4);
            break;
        }
        case AvpDataType::INTEGER64: {
            uint64_t val_be = htobe64(static_cast<uint64_t>(avp.i64_val));
            payload.resize(8);
            std::memcpy(payload.data(), &val_be, 8);
            break;
        }
        case AvpDataType::UNSIGNED64: {
            uint64_t val_be = htobe64(avp.u64_val);
            payload.resize(8);
            std::memcpy(payload.data(), &val_be, 8);
            break;
        }
        case AvpDataType::FLOAT32: {
            uint32_t bits;
            std::memcpy(&bits, &avp.f32_val, 4);
            bits = htonl(bits);
            payload.resize(4);
            std::memcpy(payload.data(), &bits, 4);
            break;
        }
        case AvpDataType::FLOAT64: {
            uint64_t bits;
            std::memcpy(&bits, &avp.f64_val, 8);
            bits = htobe64(bits);
            payload.resize(8);
            std::memcpy(payload.data(), &bits, 8);
            break;
        }
        case AvpDataType::ADDRESS: {
            // RFC 6733 Address: 2 bytes AddressType (1=IPv4) + 4 bytes IPv4
            payload.resize(6);
            uint16_t addr_type = htons(1);
            std::memcpy(payload.data(), &addr_type, 2);
            uint32_t ip_be = htonl(avp.ipv4_val);
            std::memcpy(payload.data() + 2, &ip_be, 4);
            break;
        }
        case AvpDataType::TIME: {
            uint32_t val_be = htonl(avp.time_val);
            payload.resize(4);
            std::memcpy(payload.data(), &val_be, 4);
            break;
        }
        case AvpDataType::GROUPED: {
            for (const auto& child : avp.grouped_val) {
                if (!EncodeAvp(child, payload)) {
                    return false;
                }
            }
            break;
        }
    }

    size_t payload_len = payload.size();
    size_t avp_len = header_len + payload_len;
    if (avp_len > 0x00FFFFFF) {
        return false;
    }
    size_t padded_len = (avp_len + 3) & ~3;

    size_t start_pos = out_buf.size();
    out_buf.resize(start_pos + padded_len, 0);

    // Write AVP Code (4 bytes)
    uint32_t code_be = htonl(avp.code);
    std::memcpy(out_buf.data() + start_pos, &code_be, 4);

    // Write Flags (1 byte)
    out_buf[start_pos + 4] = flags;

    // Write Length (3 bytes)
    out_buf[start_pos + 5] = static_cast<uint8_t>((avp_len >> 16) & 0xFF);
    out_buf[start_pos + 6] = static_cast<uint8_t>((avp_len >> 8) & 0xFF);
    out_buf[start_pos + 7] = static_cast<uint8_t>(avp_len & 0xFF);

    size_t data_pos = start_pos + 8;
    if (has_vendor) {
        uint32_t vendor_be = htonl(avp.vendor_id);
        std::memcpy(out_buf.data() + data_pos, &vendor_be, 4);
        data_pos += 4;
    }

    if (payload_len > 0) {
        std::memcpy(out_buf.data() + data_pos, payload.data(), payload_len);
    }

    return true;
}

bool DiameterDictionary::DecodeAvp(const uint8_t* data, size_t len, DecodedAvp& out_avp, size_t& bytes_consumed) const {
    if (!data || len < 8) {
        return false;
    }

    uint32_t code_be;
    std::memcpy(&code_be, data, 4);
    uint32_t avp_code = ntohl(code_be);

    uint8_t flags = data[4];
    uint32_t avp_len = (static_cast<uint32_t>(data[5]) << 16) |
                       (static_cast<uint32_t>(data[6]) << 8) |
                       static_cast<uint32_t>(data[7]);

    bool has_vendor = (flags & AVP_FLAG_VENDOR) != 0;
    size_t header_len = has_vendor ? 12 : 8;

    if (avp_len < header_len || len < header_len) {
        return false;
    }

    uint32_t vendor_id = 0;
    if (has_vendor) {
        uint32_t vendor_be;
        std::memcpy(&vendor_be, data + 8, 4);
        vendor_id = ntohl(vendor_be);
    }

    if (len < avp_len) {
        return false;
    }

    size_t padded_len = (avp_len + 3) & ~3;
    if (len < padded_len) {
        return false;
    }

    out_avp.code = avp_code;
    out_avp.flags = flags;
    out_avp.vendor_id = vendor_id;

    // Determine type from dictionary if available
    const AvpDefinition* def = FindAvp(avp_code, vendor_id);
    if (def) {
        out_avp.type = def->type;
    } else {
        out_avp.type = AvpDataType::OCTET_STRING;
    }

    size_t payload_len = avp_len - header_len;
    const uint8_t* payload_data = data + header_len;

    switch (out_avp.type) {
        case AvpDataType::OCTET_STRING:
            out_avp.octet_string_val.assign(payload_data, payload_data + payload_len);
            break;
        case AvpDataType::UTF8_STRING:
            out_avp.str_val.assign(reinterpret_cast<const char*>(payload_data), payload_len);
            break;
        case AvpDataType::INTEGER32: {
            if (payload_len < 4) return false;
            uint32_t val_be;
            std::memcpy(&val_be, payload_data, 4);
            out_avp.i32_val = static_cast<int32_t>(ntohl(val_be));
            break;
        }
        case AvpDataType::UNSIGNED32: {
            if (payload_len < 4) return false;
            uint32_t val_be;
            std::memcpy(&val_be, payload_data, 4);
            out_avp.u32_val = ntohl(val_be);
            break;
        }
        case AvpDataType::INTEGER64: {
            if (payload_len < 8) return false;
            uint64_t val_be;
            std::memcpy(&val_be, payload_data, 8);
            out_avp.i64_val = static_cast<int64_t>(be64toh(val_be));
            break;
        }
        case AvpDataType::UNSIGNED64: {
            if (payload_len < 8) return false;
            uint64_t val_be;
            std::memcpy(&val_be, payload_data, 8);
            out_avp.u64_val = be64toh(val_be);
            break;
        }
        case AvpDataType::FLOAT32: {
            if (payload_len < 4) return false;
            uint32_t bits;
            std::memcpy(&bits, payload_data, 4);
            bits = ntohl(bits);
            std::memcpy(&out_avp.f32_val, &bits, 4);
            break;
        }
        case AvpDataType::FLOAT64: {
            if (payload_len < 8) return false;
            uint64_t bits;
            std::memcpy(&bits, payload_data, 8);
            bits = be64toh(bits);
            std::memcpy(&out_avp.f64_val, &bits, 8);
            break;
        }
        case AvpDataType::ADDRESS: {
            if (payload_len >= 6) {
                uint16_t fam;
                std::memcpy(&fam, payload_data, 2);
                fam = ntohs(fam);
                if (fam == 1) { // IPv4
                    uint32_t ip;
                    std::memcpy(&ip, payload_data + 2, 4);
                    out_avp.ipv4_val = ntohl(ip);
                }
            } else if (payload_len == 4) {
                uint32_t ip;
                std::memcpy(&ip, payload_data, 4);
                out_avp.ipv4_val = ntohl(ip);
            }
            break;
        }
        case AvpDataType::TIME: {
            if (payload_len < 4) return false;
            uint32_t val_be;
            std::memcpy(&val_be, payload_data, 4);
            out_avp.time_val = ntohl(val_be);
            break;
        }
        case AvpDataType::GROUPED: {
            size_t inner_offset = 0;
            while (inner_offset < payload_len) {
                DecodedAvp child_avp;
                size_t child_consumed = 0;
                if (!DecodeAvp(payload_data + inner_offset, payload_len - inner_offset, child_avp, child_consumed)) {
                    return false;
                }
                if (child_consumed == 0) return false;
                out_avp.grouped_val.push_back(std::move(child_avp));
                inner_offset += child_consumed;
            }
            break;
        }
    }

    bytes_consumed = padded_len;
    return true;
}

bool DiameterDictionary::DecodeAvps(const uint8_t* data, size_t len, std::vector<DecodedAvp>& out_avps) const {
    if (!data || len == 0) return true;
    size_t offset = 0;
    while (offset < len) {
        DecodedAvp avp;
        size_t consumed = 0;
        if (!DecodeAvp(data + offset, len - offset, avp, consumed)) {
            return false;
        }
        if (consumed == 0) return false;
        out_avps.push_back(std::move(avp));
        offset += consumed;
    }
    return offset == len;
}

bool DiameterDictionary::ValidateAvp(const DecodedAvp& avp, std::string& err) const {
    const AvpDefinition* def = FindAvp(avp.code, avp.vendor_id);
    if (!def) {
        if (avp.flags & AVP_FLAG_MANDATORY) {
            err = "Mandatory AVP code " + std::to_string(avp.code) + " is unsupported / not in dictionary";
            return false;
        }
        return true;
    }

    if (avp.type != def->type) {
        err = "Data type mismatch for AVP " + def->name + " (expected " +
              std::to_string(static_cast<int>(def->type)) + ", got " +
              std::to_string(static_cast<int>(avp.type)) + ")";
        return false;
    }

    if ((def->flags & AVP_FLAG_VENDOR) && !(avp.flags & AVP_FLAG_VENDOR)) {
        err = "Vendor flag missing for vendor-specific AVP " + def->name;
        return false;
    }

    if (def->type == AvpDataType::GROUPED) {
        for (const auto& child : avp.grouped_val) {
            if (!ValidateAvp(child, err)) {
                return false;
            }
        }
        for (const auto& child_def : def->children) {
            if (child_def.flags & AVP_FLAG_MANDATORY) {
                bool found = false;
                for (const auto& child : avp.grouped_val) {
                    if (child.code == child_def.code) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    err = "Missing mandatory child AVP " + child_def.name + " inside " + def->name;
                    return false;
                }
            }
        }
    }

    return true;
}

bool DiameterDictionary::ValidateMessage(uint32_t cmd_code, uint32_t app_id, bool is_request,
                                         const std::vector<DecodedAvp>& avps, std::string& err) const {
    const CommandDefinition* cmd = FindCommand(cmd_code, app_id, is_request);
    if (!cmd) {
        err = "Unsupported command code " + std::to_string(cmd_code) +
              " (app_id " + std::to_string(app_id) + ", request=" + (is_request ? "true" : "false") + ")";
        return false;
    }

    for (uint32_t req_code : cmd->required_avps) {
        bool found = false;
        for (const auto& a : avps) {
            if (a.code == req_code) {
                found = true;
                break;
            }
        }
        if (!found) {
            const AvpDefinition* req_def = FindAvp(req_code);
            std::string name = req_def ? req_def->name : std::to_string(req_code);
            err = "Command " + cmd->name + " missing required AVP: " + name;
            return false;
        }
    }

    for (const auto& a : avps) {
        if (!ValidateAvp(a, err)) {
            return false;
        }
    }

    return true;
}

} // namespace ddos_samurai::telecom::diameter
