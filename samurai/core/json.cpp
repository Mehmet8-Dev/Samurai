#include "json.hpp"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace samurai::core::json {

// --- factories -------------------------------------------------------------

Value Value::Bool(bool b) {
  Value v;
  v.type_ = Type::Bool;
  v.bool_ = b;
  return v;
}
Value Value::Int(std::int64_t i) {
  Value v;
  v.type_ = Type::Int;
  v.int_ = i;
  return v;
}
Value Value::Double(double d) {
  Value v;
  v.type_ = Type::Double;
  v.double_ = d;
  return v;
}
Value Value::Str(std::string s) {
  Value v;
  v.type_ = Type::String;
  v.str_ = std::move(s);
  return v;
}
Value Value::Array() {
  Value v;
  v.type_ = Type::Array;
  return v;
}
Value Value::Object() {
  Value v;
  v.type_ = Type::Object;
  return v;
}

// --- accessors -------------------------------------------------------------

bool Value::as_bool(bool def) const {
  switch (type_) {
    case Type::Bool: return bool_;
    case Type::Int: return int_ != 0;
    case Type::Double: return double_ != 0.0;
    default: return def;
  }
}

std::int64_t Value::as_int(std::int64_t def) const {
  switch (type_) {
    case Type::Int: return int_;
    case Type::Double: return static_cast<std::int64_t>(double_);
    case Type::Bool: return bool_ ? 1 : 0;
    default: return def;
  }
}

double Value::as_double(double def) const {
  switch (type_) {
    case Type::Double: return double_;
    case Type::Int: return static_cast<double>(int_);
    case Type::Bool: return bool_ ? 1.0 : 0.0;
    default: return def;
  }
}

std::string Value::as_string(const std::string& def) const {
  return type_ == Type::String ? str_ : def;
}

bool Value::contains(const std::string& key) const { return find(key) != nullptr; }

const Value* Value::find(const std::string& key) const {
  for (const auto& kv : obj_) {
    if (kv.first == key) return &kv.second;
  }
  return nullptr;
}

void Value::set(const std::string& key, Value v) {
  type_ = Type::Object;
  for (auto& kv : obj_) {
    if (kv.first == key) {
      kv.second = std::move(v);
      return;
    }
  }
  obj_.emplace_back(key, std::move(v));
}

void Value::push_back(Value v) {
  type_ = Type::Array;
  arr_.push_back(std::move(v));
}

// --- serialization ---------------------------------------------------------

namespace {

void DumpString(const std::string& s, std::string& out) {
  out.push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));  // UTF-8 passthrough
        }
    }
  }
  out.push_back('"');
}

void DumpValue(const Value& v, std::string& out, bool sort_keys) {
  switch (v.type()) {
    case Value::Type::Null:
      out += "null";
      break;
    case Value::Type::Bool:
      out += v.as_bool() ? "true" : "false";
      break;
    case Value::Type::Int:
      out += std::to_string(v.as_int());
      break;
    case Value::Type::Double: {
      const double d = v.as_double();
      if (std::isfinite(d)) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.17g", d);
        out += buf;
      } else {
        out += "null";  // JSON has no Inf/NaN
      }
      break;
    }
    case Value::Type::String:
      DumpString(v.as_string(), out);
      break;
    case Value::Type::Array: {
      out.push_back('[');
      bool first = true;
      for (const auto& e : v.elements()) {
        if (!first) out.push_back(',');
        first = false;
        DumpValue(e, out, sort_keys);
      }
      out.push_back(']');
      break;
    }
    case Value::Type::Object: {
      out.push_back('{');
      const auto& members = v.members();
      if (sort_keys) {
        std::vector<const std::pair<std::string, Value>*> ptrs;
        ptrs.reserve(members.size());
        for (const auto& kv : members) ptrs.push_back(&kv);
        std::sort(ptrs.begin(), ptrs.end(),
                  [](const auto* a, const auto* b) { return a->first < b->first; });
        bool first = true;
        for (const auto* kv : ptrs) {
          if (!first) out.push_back(',');
          first = false;
          DumpString(kv->first, out);
          out.push_back(':');
          DumpValue(kv->second, out, sort_keys);
        }
      } else {
        bool first = true;
        for (const auto& kv : members) {
          if (!first) out.push_back(',');
          first = false;
          DumpString(kv.first, out);
          out.push_back(':');
          DumpValue(kv.second, out, sort_keys);
        }
      }
      out.push_back('}');
      break;
    }
  }
}

}  // namespace

std::string Value::dump(bool sort_keys) const {
  std::string out;
  DumpValue(*this, out, sort_keys);
  return out;
}

// --- parser ----------------------------------------------------------------

namespace {

class Parser {
 public:
  explicit Parser(const std::string& text) : s_(text) {}

  ParseResult Run() {
    SkipWs();
    Value v;
    if (!ParseValue(v)) return Fail();
    SkipWs();
    if (pos_ != s_.size()) {
      Error("trailing characters");
      return Fail();
    }
    ParseResult r;
    r.ok = true;
    r.value = std::move(v);
    return r;
  }

 private:
  const std::string& s_;
  std::size_t pos_ = 0;
  std::string error_;

  ParseResult Fail() {
    ParseResult r;
    r.ok = false;
    r.error = error_.empty() ? "parse error" : error_;
    return r;
  }
  bool Error(const std::string& msg) {
    if (error_.empty()) error_ = msg + " at offset " + std::to_string(pos_);
    return false;
  }

  bool Eof() const { return pos_ >= s_.size(); }
  char Peek() const { return s_[pos_]; }

  void SkipWs() {
    while (!Eof()) {
      const char c = s_[pos_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++pos_;
      } else {
        break;
      }
    }
  }

  bool ParseValue(Value& out) {
    SkipWs();
    if (Eof()) return Error("unexpected end of input");
    const char c = Peek();
    switch (c) {
      case '{': return ParseObject(out);
      case '[': return ParseArray(out);
      case '"': {
        std::string str;
        if (!ParseString(str)) return false;
        out = Value::Str(std::move(str));
        return true;
      }
      case 't':
      case 'f': return ParseBool(out);
      case 'n': return ParseNull(out);
      default:
        if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber(out);
        return Error("unexpected character");
    }
  }

  bool ParseLiteral(const char* lit) {
    for (const char* p = lit; *p; ++p) {
      if (Eof() || s_[pos_] != *p) return Error("invalid literal");
      ++pos_;
    }
    return true;
  }

  bool ParseNull(Value& out) {
    if (!ParseLiteral("null")) return false;
    out = Value::Null();
    return true;
  }

  bool ParseBool(Value& out) {
    if (Peek() == 't') {
      if (!ParseLiteral("true")) return false;
      out = Value::Bool(true);
    } else {
      if (!ParseLiteral("false")) return false;
      out = Value::Bool(false);
    }
    return true;
  }

  bool ParseNumber(Value& out) {
    const std::size_t start = pos_;
    bool is_double = false;
    if (!Eof() && Peek() == '-') ++pos_;
    while (!Eof() && Peek() >= '0' && Peek() <= '9') ++pos_;
    if (!Eof() && Peek() == '.') {
      is_double = true;
      ++pos_;
      while (!Eof() && Peek() >= '0' && Peek() <= '9') ++pos_;
    }
    if (!Eof() && (Peek() == 'e' || Peek() == 'E')) {
      is_double = true;
      ++pos_;
      if (!Eof() && (Peek() == '+' || Peek() == '-')) ++pos_;
      while (!Eof() && Peek() >= '0' && Peek() <= '9') ++pos_;
    }
    const std::string tok = s_.substr(start, pos_ - start);
    if (tok.empty() || tok == "-") return Error("invalid number");
    if (is_double) {
      out = Value::Double(std::strtod(tok.c_str(), nullptr));
    } else {
      errno = 0;
      char* end = nullptr;
      const long long ll = std::strtoll(tok.c_str(), &end, 10);
      if (errno == ERANGE) {
        out = Value::Double(std::strtod(tok.c_str(), nullptr));  // overflow -> double
      } else {
        out = Value::Int(static_cast<std::int64_t>(ll));
      }
    }
    return true;
  }

  static void EncodeUtf8(unsigned int cp, std::string& out) {
    if (cp <= 0x7F) {
      out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  bool ParseHex4(unsigned int& out) {
    if (pos_ + 4 > s_.size()) return Error("truncated \\u escape");
    unsigned int v = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = s_[pos_++];
      v <<= 4;
      if (c >= '0' && c <= '9') {
        v |= static_cast<unsigned int>(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        v |= static_cast<unsigned int>(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        v |= static_cast<unsigned int>(c - 'A' + 10);
      } else {
        return Error("invalid hex digit");
      }
    }
    out = v;
    return true;
  }

  bool ParseString(std::string& out) {
    if (Eof() || Peek() != '"') return Error("expected string");
    ++pos_;  // opening quote
    while (!Eof()) {
      const char c = s_[pos_++];
      if (c == '"') return true;
      if (c == '\\') {
        if (Eof()) return Error("truncated escape");
        const char e = s_[pos_++];
        switch (e) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': {
            unsigned int cp = 0;
            if (!ParseHex4(cp)) return false;
            if (cp >= 0xD800 && cp <= 0xDBFF) {  // high surrogate
              if (pos_ + 2 <= s_.size() && s_[pos_] == '\\' && s_[pos_ + 1] == 'u') {
                pos_ += 2;
                unsigned int lo = 0;
                if (!ParseHex4(lo)) return false;
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                  cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else {
                  EncodeUtf8(cp, out);  // unpaired; emit both as-is
                  cp = lo;
                }
              }
            }
            EncodeUtf8(cp, out);
            break;
          }
          default: return Error("invalid escape");
        }
      } else {
        out.push_back(c);
      }
    }
    return Error("unterminated string");
  }

  bool ParseArray(Value& out) {
    ++pos_;  // '['
    out = Value::Array();
    SkipWs();
    if (!Eof() && Peek() == ']') {
      ++pos_;
      return true;
    }
    while (true) {
      Value elem;
      if (!ParseValue(elem)) return false;
      out.push_back(std::move(elem));
      SkipWs();
      if (Eof()) return Error("unterminated array");
      const char c = s_[pos_++];
      if (c == ']') return true;
      if (c != ',') return Error("expected ',' or ']'");
    }
  }

  bool ParseObject(Value& out) {
    ++pos_;  // '{'
    out = Value::Object();
    SkipWs();
    if (!Eof() && Peek() == '}') {
      ++pos_;
      return true;
    }
    while (true) {
      SkipWs();
      std::string key;
      if (!ParseString(key)) return false;
      SkipWs();
      if (Eof() || s_[pos_] != ':') return Error("expected ':'");
      ++pos_;
      Value val;
      if (!ParseValue(val)) return false;
      out.set(key, std::move(val));
      SkipWs();
      if (Eof()) return Error("unterminated object");
      const char c = s_[pos_++];
      if (c == '}') return true;
      if (c != ',') return Error("expected ',' or '}'");
    }
  }
};

}  // namespace

ParseResult Parse(const std::string& text) { return Parser(text).Run(); }

}  // namespace samurai::core::json
