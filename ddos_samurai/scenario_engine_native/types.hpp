#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ddos_samurai::scenario_native {

enum class StepType : std::uint8_t {
  Request = 0,
  Pause = 1,
  Branch = 2,
  Loop = 3,
  Assert = 4,
  EndSession = 5,
  TcpConnect = 6,
  TcpSend = 7,
  TcpExpect = 8,
  TcpClose = 9,
};

struct ThinkTime {
  int min_ms{0};
  int max_ms{0};
  std::string distribution{"uniform"};
  int mean_ms{0};
  int stddev_ms{0};
};

struct Step {
  StepType type{StepType::Request};
  std::string method{"GET"};
  std::string path{"/"};
  std::string body_template{};
  std::string flow{};
  int repeat{1};
  double probability{1.0};
  std::string on_failure{"retry"};
  std::uint16_t dst_port{0};
  std::string payload_template{};
  std::string condition{};
  int timeout_ms{0};
  ThinkTime think_time{};
};

struct Persona {
  std::string name{};
  std::string device_profile{"web"};
  std::unordered_map<std::string, std::string> headers{};
  std::unordered_map<std::string, std::string> cookies{};
  int request_timeout_ms{5000};
  int session_timeout_ms{0};
  int max_retries{0};
  double weight{1.0};
};

struct Flow {
  std::string name{};
  std::string persona{};
  std::vector<Step> steps{};
};

struct LoadModel {
  std::string backend{"http"};
  int concurrent_vus{0};
  int ramp_seconds{0};
};

struct ScenarioSpecNative {
  std::vector<Flow> flows{};
  std::unordered_map<std::string, std::size_t> flow_index{};
  std::unordered_map<std::string, Persona> personas{};
  LoadModel load_model{};
};

}  // namespace ddos_samurai::scenario_native
