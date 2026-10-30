#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <string_view>

namespace ddos_samurai::telecom::diameter {

// RFC 6733 AVP Data Types
enum class AvpDataType : uint8_t {
    OCTET_STRING = 0,
    INTEGER32,
    INTEGER64,
    UNSIGNED32,
    UNSIGNED64,
    FLOAT32,
    FLOAT64,
    ADDRESS,
    TIME,
    UTF8_STRING,
    GROUPED
};

// RFC 6733 AVP Header Flag Bits
constexpr uint8_t AVP_FLAG_VENDOR    = 0x80; // V-bit
constexpr uint8_t AVP_FLAG_MANDATORY = 0x40; // M-bit
constexpr uint8_t AVP_FLAG_PROTECTED = 0x20; // P-bit

// Forward declaration
struct AvpDefinition;

// AVP Definition in Dictionary
struct AvpDefinition {
    uint32_t code{0};
    uint32_t vendor_id{0}; // 0 = IETF standard, 10415 = 3GPP
    std::string name;
    AvpDataType type{AvpDataType::OCTET_STRING};
    uint8_t flags{AVP_FLAG_MANDATORY};
    std::vector<AvpDefinition> children; // Child definitions if type == GROUPED
};

// Command Definition in Dictionary
struct CommandDefinition {
    uint32_t code{0};
    uint32_t app_id{0}; // 0 = Base Common, 4 = Ro RFC 4006, 16777216 = 3GPP Gx
    std::string name;
    bool is_request{true};
    std::vector<uint32_t> required_avps;
    std::vector<uint32_t> optional_avps;
};

// Decoded Dynamic AVP Representation
struct DecodedAvp {
    uint32_t code{0};
    uint32_t vendor_id{0};
    uint8_t flags{AVP_FLAG_MANDATORY};
    AvpDataType type{AvpDataType::OCTET_STRING};

    std::vector<uint8_t> octet_string_val;
    int32_t i32_val{0};
    int64_t i64_val{0};
    uint32_t u32_val{0};
    uint64_t u64_val{0};
    float f32_val{0.0f};
    double f64_val{0.0};
    uint32_t ipv4_val{0};
    uint32_t time_val{0};
    std::string str_val;
    std::vector<DecodedAvp> grouped_val;

    // Helper static constructors
    static DecodedAvp CreateString(uint32_t code, const std::string& str, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateU32(uint32_t code, uint32_t val, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateU64(uint32_t code, uint64_t val, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateI32(uint32_t code, int32_t val, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateI64(uint32_t code, int64_t val, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateFloat32(uint32_t code, float val, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateFloat64(uint32_t code, double val, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateAddressIpv4(uint32_t code, uint32_t ip, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateTime(uint32_t code, uint32_t ntp_secs, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateOctetString(uint32_t code, const std::vector<uint8_t>& octets, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
    static DecodedAvp CreateGrouped(uint32_t code, std::vector<DecodedAvp> children, uint8_t flags = AVP_FLAG_MANDATORY, uint32_t vendor_id = 0);
};

class DiameterDictionary {
public:
    DiameterDictionary();
    ~DiameterDictionary() = default;

    // Load built-in carrier dictionary (RFC 6733 Base + 3GPP Ro/Gx/Gy)
    void LoadBuiltinCarrierDictionary();

    // Register / add definition
    void AddAvpDefinition(const AvpDefinition& def);
    void AddCommandDefinition(const CommandDefinition& def);

    // Dynamic schema loader from JSON
    bool LoadFromJson(const std::string& json_str, std::string* error_msg = nullptr);

    // Lookups
    const AvpDefinition* FindAvp(uint32_t code, uint32_t vendor_id = 0) const noexcept;
    const AvpDefinition* FindAvpByName(const std::string& name) const noexcept;
    const CommandDefinition* FindCommand(uint32_t code, uint32_t app_id, bool is_request) const noexcept;
    const CommandDefinition* FindCommandByName(const std::string& name, bool is_request) const noexcept;

    // Codec methods
    bool EncodeAvp(const DecodedAvp& avp, std::vector<uint8_t>& out_buf) const;
    bool DecodeAvp(const uint8_t* data, size_t len, DecodedAvp& out_avp, size_t& bytes_consumed) const;
    bool DecodeAvps(const uint8_t* data, size_t len, std::vector<DecodedAvp>& out_avps) const;

    // Schema validation
    bool ValidateAvp(const DecodedAvp& avp, std::string& err) const;
    bool ValidateMessage(uint32_t cmd_code, uint32_t app_id, bool is_request,
                         const std::vector<DecodedAvp>& avps, std::string& err) const;

    // Clear dictionary
    void Clear();

    size_t AvpCount() const noexcept { return avp_by_key_.size(); }
    size_t CommandCount() const noexcept { return commands_.size(); }

private:
    static uint64_t MakeAvpKey(uint32_t code, uint32_t vendor_id) noexcept {
        return (static_cast<uint64_t>(vendor_id) << 32) | static_cast<uint64_t>(code);
    }

    static uint64_t MakeCommandKey(uint32_t code, uint32_t app_id, bool is_request) noexcept {
        uint64_t req_bit = is_request ? 0x8000000000000000ULL : 0ULL;
        return req_bit | (static_cast<uint64_t>(app_id) << 32) | static_cast<uint64_t>(code);
    }

    std::unordered_map<uint64_t, AvpDefinition> avp_by_key_;
    std::unordered_map<std::string, uint64_t> avp_by_name_;
    std::unordered_map<uint64_t, CommandDefinition> commands_;
    std::unordered_map<std::string, uint64_t> commands_by_name_;
};

} // namespace ddos_samurai::telecom::diameter
