// samurai — native CLI entrypoint.
//
// Thin driver: parse (args) -> validate (validation) -> run the job via the
// orchestrator's ZMQ supervisor.

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include "args.hpp"
#include "config_loader.hpp"
#include "json.hpp"
#include "kpi_gate.hpp"
#include "options.hpp"
#include "profiles.hpp"
#include "reporting.hpp"
#include "rfc_suite.hpp"
#include "run_summary.hpp"
#include "setup_tools.hpp"
#include "supervisor.hpp"
#include "validation.hpp"
#include "worker_registry.hpp"

int main(int argc, char** argv) {
  using namespace samurai;

  if (argc >= 2 && std::string(argv[1]) == "build") {
    namespace fs = std::filesystem;
    std::string source_dir = "samurai";
    std::string build_dir = "build";
    std::string prefix_dir;
    bool portable = false;
    unsigned jobs = std::max(1u, std::thread::hardware_concurrency());

    for (int i = 2; i < argc; ++i) {
      const std::string a = argv[i];
      if (a == "-h" || a == "--help") {
        std::printf(
            "usage: %s build [--source DIR] [--build-dir DIR] [--prefix DIR] [--jobs N] [--portable]\n"
            "\n"
            "Compiles all Samurai binaries and hardware-accelerated workers (CPU -march=native,\n"
            "CUDA, DPDK, AF_XDP, io_uring, DOCA) natively for this machine.\n",
            argv[0]);
        return 0;
      } else if (a == "--source" && i + 1 < argc) {
        source_dir = argv[++i];
      } else if (a == "--build-dir" && i + 1 < argc) {
        build_dir = argv[++i];
      } else if (a == "--prefix" && i + 1 < argc) {
        prefix_dir = argv[++i];
      } else if ((a == "--jobs" || a == "-j") && i + 1 < argc) {
        jobs = static_cast<unsigned>(std::max(1L, std::strtol(argv[++i], nullptr, 10)));
      } else if (a == "--portable") {
        portable = true;
      } else {
        std::fprintf(stderr, "samurai build: unknown option '%s'\n", a.c_str());
        return 2;
      }
    }

    std::error_code ec;
    if (!fs::exists(fs::path(source_dir) / "CMakeLists.txt", ec)) {
      std::fprintf(stderr,
                   "samurai build: '%s/CMakeLists.txt' not found.\n"
                   "Run inside a Samurai source checkout or use 'npx -y samurai-net build' to download & compile for this machine.\n",
                   source_dir.c_str());
      return 2;
    }

    auto run_exec = [](const std::vector<std::string>& cmd) -> int {
      const pid_t pid = ::fork();
      if (pid == 0) {
        std::vector<char*> c_args;
        c_args.reserve(cmd.size() + 1);
        for (const auto& s : cmd) c_args.push_back(const_cast<char*>(s.c_str()));
        c_args.push_back(nullptr);
        ::execvp(c_args[0], c_args.data());
        std::fprintf(stderr, "samurai build: failed to exec '%s'\n", c_args[0]);
        _exit(127);
      }
      if (pid < 0) return 1;
      int st = 0;
      ::waitpid(pid, &st, 0);
      return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    };

    const std::string arch_opt = std::string("-DSAMURAI_NATIVE_ARCH=") + (portable ? "OFF" : "ON");
    std::printf("[samurai build] Configuring (%s, jobs=%u)...\n", arch_opt.c_str(), jobs);
    if (run_exec({"cmake", "-B", build_dir, "-S", source_dir, "-DCMAKE_BUILD_TYPE=Release", arch_opt}) != 0) {
      return 1;
    }
    std::printf("[samurai build] Compiling native targets for this host...\n");
    if (run_exec({"cmake", "--build", build_dir, "-j", std::to_string(jobs)}) != 0) {
      return 1;
    }

    if (!prefix_dir.empty()) {
      const fs::path bin_dst = fs::path(prefix_dir) / "bin";
      fs::create_directories(bin_dst, ec);
      const std::vector<std::pair<std::string, std::string>> artifacts = {
          {"cli/samurai", "samurai"},
          {"mcp/samurai_mcp", "samurai_mcp"},
          {"control/daemon/samurai_master", "samurai_master"},
          {"control/daemon/samurai_slave", "samurai_slave"},
          {"zmq/samurai_cpu_worker", "samurai_cpu_worker"},
          {"zmq/samurai_afpacket_worker", "samurai_afpacket_worker"},
          {"zmq/samurai_afxdp_worker", "samurai_afxdp_worker"},
          {"zmq/samurai_dpdk_worker", "samurai_dpdk_worker"},
          {"zmq/samurai_gpu_worker", "samurai_gpu_worker"},
          {"zmq/samurai_doca_worker", "samurai_doca_worker"},
          {"zmq/samurai_l7_worker", "samurai_l7_worker"},
          {"zmq/samurai_scenario_worker", "samurai_scenario_worker"},
          {"zmq/samurai_defense_worker", "samurai_defense_worker"},
          {"zmq/samurai_telco_worker", "samurai_telco_worker"},
          {"l4/test_100k_tcp_flows", "samurai_bench_100k_tcp"},
          {"l4/test_1m_tcp_flows", "samurai_bench_1m_tcp"},
          {"zmq/bench_l7_stateful_userspace", "samurai_bench_l7"},
      };
      for (const auto& item : artifacts) {
        const fs::path src = fs::path(build_dir) / item.first;
        if (fs::exists(src, ec)) {
          fs::copy_file(src, bin_dst / item.second, fs::copy_options::overwrite_existing, ec);
        }
      }
      const fs::path cuda_so = fs::path(source_dir) / "libgpu_packet_cuda.so";
      if (fs::exists(cuda_so, ec)) {
        fs::copy_file(cuda_so, bin_dst / "libgpu_packet_cuda.so", fs::copy_options::overwrite_existing, ec);
      }
      const fs::path src_skills = fs::path(source_dir).parent_path() / "skills";
      if (fs::is_directory(src_skills, ec)) {
        fs::copy(src_skills, fs::path(prefix_dir) / "skills",
                 fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
      }
      std::printf("[samurai build] Installed native host binaries to %s\n", bin_dst.string().c_str());
    }
    return 0;
  }

  if (argc >= 2 && std::string(argv[1]) == "mcp") {
    if (argc >= 3 && std::string(argv[2]) == "doctor") {
      return mcp::RunDoctorCli(argc - 3, argv + 3);
    }
    if (argc >= 3 && std::string(argv[2]) == "setup") {
      return mcp::RunSetupCli(argc - 3, argv + 3);
    }
    std::printf(
        "usage: %s mcp <doctor|setup> [options]\n"
        "  samurai mcp doctor [--client <id>] [--json]\n"
        "  samurai mcp setup  --client <id> [--yes] [--docker | --npx] [--ghcr] [--scope user|project] [--json]\n",
        argv[0]);
    return (argc == 2 || (argc >= 3 && (std::string(argv[2]) == "-h" || std::string(argv[2]) == "--help")))
               ? 0
               : 2;
  }

  cli::CliOptions opt;
  const cli::ParseStatus status = cli::ParseArgs(argc, argv, opt);
  if (status == cli::ParseStatus::kHelp) {
    cli::PrintUsage(argv[0]);
    return 0;
  }
  if (status == cli::ParseStatus::kError) {
    cli::PrintUsage(argv[0]);
    return 2;
  }
  if (opt.list_profiles) {
    cli::ListProfiles();
    return 0;
  }

  // Load samurai.conf (with overwrite=0 so user env vars always win over file).
  const auto cfg_res = cli::LoadConfigFile(opt.config_path);
  if (cfg_res.error) {
    std::fprintf(stderr, "samurai: %s\n", cfg_res.error_msg.c_str());
    return 2;
  }
  if (!opt.log_level.empty()) {
    ::setenv("SAMURAI_LOG_LEVEL", opt.log_level.c_str(), 1);
  }

  auto to_lower_copy = [](std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
  };
  auto infer_scenario_protocol = [&](const std::string& path) -> std::string {
    if (path.empty()) return "http1";
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return "http1";
    std::ostringstream oss;
    oss << in.rdbuf();
    const auto parsed = core::json::Parse(oss.str());
    if (!parsed.ok || !parsed.value.is_object()) return "http1";
    const auto& doc = parsed.value;
    bool has_http = false;
    bool has_l4_tcp = false;
    if (const auto* flows = doc.find("flows"); flows && flows->is_object()) {
      for (const auto& fkv : flows->members()) {
        const auto* steps = fkv.second.find("steps");
        if (!steps || !steps->is_array()) continue;
        for (const auto& st : steps->elements()) {
          if (!st.is_object()) continue;
          std::string t;
          if (const auto* tv = st.find("type"); tv && tv->is_string()) t = tv->as_string();
          if (t.empty()) {
            if (const auto* kv = st.find("kind"); kv && kv->is_string()) t = kv->as_string();
          }
          t = to_lower_copy(t);
          if (t.empty() || t == "request") has_http = true;
          else if (t == "tcp_connect" || t == "tcp_send" || t == "tcp_expect" || t == "tcp_close") has_l4_tcp = true;
        }
      }
    }
    if (has_l4_tcp && !has_http) return "tcp";
    std::string req;
    if (const auto* lm = doc.find("load_model"); lm && lm->is_object()) {
      if (const auto* b = lm->find("backend"); b && b->is_string()) req = to_lower_copy(b->as_string());
    }
    if (const auto* p = doc.find("protocol"); p && p->is_string()) req = to_lower_copy(p->as_string());
    if (req == "http2" || req == "h2") return "http2";
    if (req == "http3" || req == "h3" || req == "quic") return "quic";
    if (req == "tcp") return "tcp";
    return "http1";
  };

  const bool is_rfc_run = !opt.run_rfc_suite.empty();
  if (opt.worker_name == "l7") {
    if (opt.job.protocol == "udp") opt.job.protocol = "http1";
    if (!opt.vector_explicit && opt.job.attack_vector == "flood") {
      opt.job.attack_vector = is_rfc_run ? "basic" : "http";
    }
  } else if (opt.worker_name == "scenario") {
    if (opt.job.protocol == "udp") {
      opt.job.protocol = infer_scenario_protocol(opt.job.l7_profile_file);
    }
    if (!opt.vector_explicit && opt.job.attack_vector == "flood") {
      opt.job.attack_vector = "scenario";
    }
  }

  if (is_rfc_run) {
    if (opt.worker_name.empty()) {
      opt.worker_name = "cpu";
    }
    if (!opt.vector_explicit && opt.job.attack_vector == "flood") {
      opt.job.attack_vector = "basic";
    }
  }

  if (const auto err = cli::Validate(opt)) {
    std::fprintf(stderr, "samurai: %s\n", err->c_str());
    return 2;
  }

  if (is_rfc_run) {
    const std::string& rfc_suite = opt.run_rfc_suite;
    if (rfc_suite != "all" && rfc_suite != "rfc2544" && rfc_suite != "2544" &&
        rfc_suite != "rfc3511" && rfc_suite != "3511" && rfc_suite != "rfc8219" && rfc_suite != "8219") {
      std::fprintf(stderr,
                   "samurai: invalid --run-rfc-suite '%s' (expected rfc2544|rfc3511|rfc8219|all)\n",
                   rfc_suite.c_str());
      return 2;
    }
    if (!opt.confirm || opt.job.target_ip.empty()) {
      std::fprintf(stderr,
                   "samurai: --run-rfc-suite requires --confirm and a live target (--target <ip> --port <p> --worker <name>)\n");
      return 2;
    }

    cli::Rfc2544Config c2544;
    cli::Rfc3511Config c3511;
    cli::Rfc8219Config c8219;
    if (opt.job.packet_size > 0) {
      c2544.packet_size_bytes = opt.job.packet_size;
    }
    if (opt.job.target_rps > 0.0) {
      c2544.max_rate_rps = opt.job.target_rps;
      c2544.min_rate_rps = std::max(1.0, std::min(1000.0, opt.job.target_rps * 0.05));
      c2544.resolution_rps = std::max(5.0, c2544.max_rate_rps * 0.15);
      c2544.trial_duration_s = std::clamp(
          static_cast<double>(std::max<uint32_t>(1, opt.job.packet_count)) /
              std::max(1.0, c2544.max_rate_rps),
          0.1,
          5.0);
      c3511.target_cps = (opt.worker_name == "telco" && opt.job.telco_rate_cps > 0)
                             ? static_cast<double>(opt.job.telco_rate_cps)
                             : opt.job.target_rps;
    } else if (opt.worker_name == "telco" && opt.job.telco_rate_cps > 0) {
      c3511.target_cps = static_cast<double>(opt.job.telco_rate_cps);
    }

    const auto rfc_entry = orchestrator::LookupWorker(opt.worker_name);
    if (!rfc_entry.has_value()) {
      std::fprintf(stderr, "samurai: worker '%s' not available for --run-rfc-suite\n", opt.worker_name.c_str());
      return 2;
    }

    orchestrator::WarmWorkerPool rfc_pool;
    const std::string suffix = std::to_string(static_cast<long>(getpid()));
    orchestrator::SupervisorConfig sup_cfg;
    sup_cfg.worker = *rfc_entry;
    sup_cfg.worker_dir = opt.worker_dir;
    sup_cfg.jobs_endpoint = "ipc:///tmp/samurai_jobs_rfc_" + suffix;
    sup_cfg.events_endpoint = "ipc:///tmp/samurai_events_rfc_" + suffix;
    sup_cfg.recv_timeout_ms = opt.timeout_ms;
    sup_cfg.iface = opt.iface;
    sup_cfg.transport = opt.transport;
    sup_cfg.dpdk_port = opt.dpdk_port;
    sup_cfg.dpdk_queue = opt.dpdk_queue;

    auto trial_runner = [sup_cfg, opt, c2544, &rfc_pool](double trial_rps) -> cli::Rfc2544Trial {
      orchestrator::JobOptions job = opt.job;
      job.target_rps = trial_rps;
      job.pacing_mode = trial_rps > 0.0 ? 1u : 0u;
      const double duration = std::max(0.1, c2544.trial_duration_s);
      job.packet_count = static_cast<uint32_t>(std::max(1.0, trial_rps * duration));
      if (job.telco_duration_ms == 0) {
        job.telco_duration_ms = static_cast<std::uint32_t>(duration * 1000.0);
      }
      orchestrator::RunStats stats;
      const int rc = orchestrator::RunJob(sup_cfg, job, stats, &rfc_pool, nullptr, "rfc-suite");
      cli::Rfc2544Trial trial;
      trial.rate_rps = (stats.actual_rps > 0.0) ? stats.actual_rps : trial_rps;
      trial.sent_packets = stats.attempted;
      trial.received_packets = (stats.sent >= stats.errors) ? (stats.sent - stats.errors) : 0;
      trial.loss_pct = (rc != 0 || stats.attempted == 0)
                           ? 100.0
                           : std::clamp(stats.wire_loss_est_pct, 0.0, 100.0);
      return trial;
    };

    auto cps_runner = [sup_cfg, opt, &rfc_pool](double target_cps) -> cli::Rfc3511Sample {
      orchestrator::JobOptions job = opt.job;
      job.target_rps = target_cps;
      job.pacing_mode = target_cps > 0.0 ? 1u : 0u;
      job.packet_count = (opt.job.target_rps > 0.0)
                             ? std::max<uint32_t>(1, opt.job.packet_count)
                             : static_cast<uint32_t>(std::max(1.0, target_cps * 2.0));
      job.telco_rate_cps = static_cast<std::uint32_t>(std::max(1.0, target_cps));
      orchestrator::RunStats stats;
      const auto t0 = std::chrono::steady_clock::now();
      const int rc = orchestrator::RunJob(sup_cfg, job, stats, &rfc_pool, nullptr, "rfc-suite");
      const double elapsed_ms =
          std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
      cli::Rfc3511Sample sample;
      sample.ok = (rc == 0 && stats.attempted > 0);
      sample.achieved_cps =
          (stats.telco_current_cps > 0) ? static_cast<double>(stats.telco_current_cps) : stats.actual_rps;
      if (stats.l7_request_latency_p99_ms > 0.0) {
        sample.p99_latency_ms = stats.l7_request_latency_p99_ms;
      } else if (stats.telco_p99_setup_latency_us > 0) {
        sample.p99_latency_ms = static_cast<double>(stats.telco_p99_setup_latency_us) / 1000.0;
      } else if (stats.telco_avg_setup_latency_us > 0) {
        sample.p99_latency_ms = static_cast<double>(stats.telco_avg_setup_latency_us) / 1000.0;
      } else {
        sample.p99_latency_ms = elapsed_ms / static_cast<double>(std::max<std::uint64_t>(1, stats.sent));
      }
      if (opt.job.concurrency > 1) {
        sample.max_concurrency = opt.job.concurrency;
      } else if (opt.worker_name == "telco" && opt.job.telco_subscribers > 0) {
        sample.max_concurrency = opt.job.telco_subscribers;
      } else {
        sample.max_concurrency = static_cast<uint32_t>(std::min<std::uint64_t>(
            stats.sent, static_cast<std::uint64_t>(UINT32_MAX)));
      }
      return sample;
    };

    auto inspection_runner = [sup_cfg, opt, &rfc_pool](double) -> cli::Rfc8219Sample {
      orchestrator::JobOptions job = opt.job;
      orchestrator::RunStats stats;
      const auto t0 = std::chrono::steady_clock::now();
      const int rc = orchestrator::RunJob(sup_cfg, job, stats, &rfc_pool, nullptr, "rfc-suite");
      const double elapsed_s = std::max(
          1e-6, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
      cli::Rfc8219Sample sample;
      sample.ok = (rc == 0 && stats.attempted > 0);
      sample.inspection_pass_rate_pct =
          sample.ok ? std::clamp(100.0 - stats.wire_loss_est_pct, 0.0, 100.0) : 0.0;
      if (stats.bytes_sent > 0) {
        sample.measured_gbps = (static_cast<double>(stats.bytes_sent) * 8.0) / (elapsed_s * 1e9);
      } else {
        sample.measured_gbps = (stats.actual_rps * static_cast<double>(opt.job.packet_size) * 8.0) / 1e9;
      }
      return sample;
    };

    const cli::RfcSuiteResult res = cli::RfcSuiteEngine::RunAllMeasured(
        c2544, c3511, c8219, trial_runner, cps_runner, inspection_runner, true, rfc_suite);
    const std::string md_report = cli::RfcReportGenerator::GenerateMarkdownReport(res);
    const std::string html_report = cli::RfcReportGenerator::GenerateHtmlReport(res);
    std::printf("%s\n", md_report.c_str());

    if (!opt.rfc_report_out.empty()) {
      if (!cli::WriteReportFile(opt.rfc_report_out, html_report)) {
        std::fprintf(stderr, "samurai: failed to write RFC report to %s\n", opt.rfc_report_out.c_str());
      } else {
        std::printf("RFC Benchmark HTML Report written to: %s\n", opt.rfc_report_out.c_str());
      }
    }
    return res.overall_passed ? 0 : 3;
  }

  const auto entry = orchestrator::LookupWorker(opt.worker_name);
  // Validate() already guaranteed this lookup succeeds.
  const std::string suffix = std::to_string(static_cast<long>(getpid()));
  orchestrator::SupervisorConfig cfg;
  cfg.worker = *entry;
  cfg.worker_dir = opt.worker_dir;
  cfg.jobs_endpoint = "ipc:///tmp/samurai_jobs_" + suffix;
  cfg.events_endpoint = "ipc:///tmp/samurai_events_" + suffix;
  cfg.recv_timeout_ms = opt.timeout_ms;
  cfg.output_mode = opt.output_mode;
  cfg.iface = opt.iface;
  cfg.transport = opt.transport;
  cfg.dpdk_port = opt.dpdk_port;
  cfg.dpdk_queue = opt.dpdk_queue;

  orchestrator::RunStats stats;
  int run_status = orchestrator::RunJob(cfg, opt.job, stats);

  // KPI gate: evaluate thresholds against the run stats.
  const cli::KpiGateResult gate = cli::EvaluateKpiGate(opt.kpi, stats);
  if (gate.evaluated) {
    std::printf("%s\n", cli::KpiGateJson(gate).c_str());
    if (!gate.passed && run_status == 0) {
      run_status = 3;  // gate failure surfaces as a non-zero exit
    }
  }

  // Reports.
  if (!opt.report_json_path.empty() || !opt.report_text_path.empty()) {
    cli::RunReport report;
    report.worker_name = opt.worker_name;
    report.job = opt.job;
    report.stats = stats;
    report.gate = gate;
    report.exit_status = run_status;
    if (!opt.report_json_path.empty() &&
        !cli::WriteReportFile(opt.report_json_path, cli::ReportJson(report))) {
      std::fprintf(stderr, "samurai: failed to write %s\n", opt.report_json_path.c_str());
    }
    if (!opt.report_text_path.empty() &&
        !cli::WriteReportFile(opt.report_text_path, cli::ReportText(report))) {
      std::fprintf(stderr, "samurai: failed to write %s\n", opt.report_text_path.c_str());
    }
  }

  return run_status;
}
