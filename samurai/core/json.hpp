#pragma once

// Minimal, dependency-free JSON value + parser + serializer for the native
// control plane. The ZMQ workers use the fixed binary wire protocol and need no
// JSON; the control-plane layers (JWT claims, telemetry, management API) do, so
// this lives in samurai_core as the shared implementation.
//
// Objects preserve insertion order (so serialization is reproducible, e.g. for
// JWT signing). Supports null/bool/int/double/string/array/object with full
// string escaping incl. \uXXXX (surrogate pairs -> UTF-8).

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace samurai::core::json {

class Value {
 public:
  enum class Type { Null, Bool, Int, Double, String, Array, Object };

  Value() = default;

  static Value Null() { return Value(); }
  static Value Bool(bool b);
  static Value Int(std::int64_t i);
  static Value Double(double d);
  static Value Str(std::string s);
  static Value Array();
  static Value Object();

  Type type() const { return type_; }
  bool is_null() const { return type_ == Type::Null; }
  bool is_bool() const { return type_ == Type::Bool; }
  bool is_int() const { return type_ == Type::Int; }
  bool is_double() const { return type_ == Type::Double; }
  bool is_number() const { return type_ == Type::Int || type_ == Type::Double; }
  bool is_string() const { return type_ == Type::String; }
  bool is_array() const { return type_ == Type::Array; }
  bool is_object() const { return type_ == Type::Object; }

  bool as_bool(bool def = false) const;
  std::int64_t as_int(std::int64_t def = 0) const;   // Double/Bool coerced
  double as_double(double def = 0.0) const;
  std::string as_string(const std::string& def = "") const;

  // Object access.
  bool contains(const std::string& key) const;
  const Value* find(const std::string& key) const;
  void set(const std::string& key, Value v);  // replaces existing key in place
  const std::vector<std::pair<std::string, Value>>& members() const { return obj_; }

  // Array access.
  void push_back(Value v);
  const std::vector<Value>& elements() const { return arr_; }

  // Compact serialization: no spaces after ',' or ':'. With sort_keys, object
  // keys are emitted in lexicographic (byte) order at every level, for
  // deterministic hashing.
  std::string dump(bool sort_keys = false) const;

 private:
  Type type_ = Type::Null;
  bool bool_ = false;
  std::int64_t int_ = 0;
  double double_ = 0.0;
  std::string str_;
  std::vector<Value> arr_;
  std::vector<std::pair<std::string, Value>> obj_;
};

struct ParseResult {
  bool ok = false;
  Value value;
  std::string error;
};

// Parse a complete JSON document. Trailing non-whitespace is an error.
ParseResult Parse(const std::string& text);

}  // namespace samurai::core::json
