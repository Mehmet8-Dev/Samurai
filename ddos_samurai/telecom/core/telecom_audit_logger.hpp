#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>

#include "ddos_samurai/core/json.hpp"

namespace ddos_samurai::telecom {

/**
 * @brief Carrier-Grade RFC 2544 / RFC 2889 Telemetry Audit Record
 * 
 * Complies with the standard schema defined in plan/03_DIRECTORY_STRUCTURE_AND_CPP_SKELETONS.md:
 * test_id,protocol,subscriber_count,active_sessions,session_setup_rate_cps,
 * session_failure_rate_pct,packets_per_second,rx_drops,tx_errors,
 * cpu_utilization_pct,memory_usage_mb,test_duration_s,hardware_spec
 */
struct TelcoAuditRecord {
    std::string test_id;
    std::string protocol;
    uint32_t subscriber_count = 0;
    uint32_t active_sessions = 0;
    double session_setup_rate_cps = 0.0;
    double session_failure_rate_pct = 0.0;
    uint64_t packets_per_second = 0;
    uint64_t rx_drops = 0;
    uint64_t tx_errors = 0;
    double cpu_utilization_pct = 0.0;
    double memory_usage_mb = 0.0;
    double test_duration_s = 0.0;
    std::string hardware_spec = "Local Veth/Loopback (No Physical NIC RFC 2544 certified)";

    // Extended RFC 2544 / RFC 2889 Carrier-Grade Verification Metrics
    uint64_t tx_frames = 0;
    uint64_t rx_frames = 0;
    double frame_loss_pct = 0.0;
    double throughput_mbps = 0.0;
    double min_latency_us = 0.0;
    double avg_latency_us = 0.0;
    double p95_latency_us = 0.0;
    double p99_latency_us = 0.0;
    double max_latency_us = 0.0;

    /**
     * @brief Computes mathematically consistent derived metrics
     */
    void ComputeDerivedMetrics() noexcept {
        if (subscriber_count > 0 && active_sessions <= subscriber_count) {
            uint32_t failed = subscriber_count - active_sessions;
            session_failure_rate_pct = (static_cast<double>(failed) * 100.0) / subscriber_count;
        }
        if (test_duration_s > 0.0 && session_setup_rate_cps == 0.0 && active_sessions > 0) {
            session_setup_rate_cps = static_cast<double>(active_sessions) / test_duration_s;
        }
        if (tx_frames > 0) {
            if (rx_frames <= tx_frames) {
                frame_loss_pct = static_cast<double>(tx_frames - rx_frames) * 100.0 / static_cast<double>(tx_frames);
            } else {
                frame_loss_pct = 0.0;
            }
        }
        if (test_duration_s > 0.0 && packets_per_second == 0 && tx_frames > 0) {
            packets_per_second = static_cast<uint64_t>(static_cast<double>(tx_frames) / test_duration_s);
        }
    }

    /**
     * @brief Exports record in standard CSV row format
     */
    std::string ToCsvRow() const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2);
        ss << test_id << ","
           << protocol << ","
           << subscriber_count << ","
           << active_sessions << ","
           << session_setup_rate_cps << ","
           << session_failure_rate_pct << ","
           << packets_per_second << ","
           << rx_drops << ","
           << tx_errors << ","
           << cpu_utilization_pct << ","
           << memory_usage_mb << ","
           << test_duration_s << ","
           << "\"" << hardware_spec << "\"";
        return ss.str();
    }

    /**
     * @brief Exports record to JSON value
     */
    samurai::core::json::Value ToJson() const {
        auto obj = samurai::core::json::Value::Object();
        obj.set("test_id", samurai::core::json::Value::Str(test_id));
        obj.set("protocol", samurai::core::json::Value::Str(protocol));
        obj.set("subscriber_count", samurai::core::json::Value::Int(subscriber_count));
        obj.set("active_sessions", samurai::core::json::Value::Int(active_sessions));
        obj.set("session_setup_rate_cps", samurai::core::json::Value::Double(session_setup_rate_cps));
        obj.set("session_failure_rate_pct", samurai::core::json::Value::Double(session_failure_rate_pct));
        obj.set("packets_per_second", samurai::core::json::Value::Int(static_cast<std::int64_t>(packets_per_second)));
        obj.set("rx_drops", samurai::core::json::Value::Int(static_cast<std::int64_t>(rx_drops)));
        obj.set("tx_errors", samurai::core::json::Value::Int(static_cast<std::int64_t>(tx_errors)));
        obj.set("cpu_utilization_pct", samurai::core::json::Value::Double(cpu_utilization_pct));
        obj.set("memory_usage_mb", samurai::core::json::Value::Double(memory_usage_mb));
        obj.set("test_duration_s", samurai::core::json::Value::Double(test_duration_s));
        obj.set("hardware_spec", samurai::core::json::Value::Str(hardware_spec));

        // RFC 2544 fields
        auto rfc = samurai::core::json::Value::Object();
        rfc.set("tx_frames", samurai::core::json::Value::Int(static_cast<std::int64_t>(tx_frames)));
        rfc.set("rx_frames", samurai::core::json::Value::Int(static_cast<std::int64_t>(rx_frames)));
        rfc.set("frame_loss_pct", samurai::core::json::Value::Double(frame_loss_pct));
        rfc.set("throughput_mbps", samurai::core::json::Value::Double(throughput_mbps));
        rfc.set("min_latency_us", samurai::core::json::Value::Double(min_latency_us));
        rfc.set("avg_latency_us", samurai::core::json::Value::Double(avg_latency_us));
        rfc.set("p95_latency_us", samurai::core::json::Value::Double(p95_latency_us));
        rfc.set("p99_latency_us", samurai::core::json::Value::Double(p99_latency_us));
        rfc.set("max_latency_us", samurai::core::json::Value::Double(max_latency_us));
        obj.set("rfc2544", std::move(rfc));

        return obj;
    }
};

/**
 * @brief Thread-safe Telecom Telemetry Audit Logger & Exporter
 */
class TelecomAuditLogger {
public:
    static TelecomAuditLogger& Instance() {
        static TelecomAuditLogger s_instance;
        return s_instance;
    }

    void Record(TelcoAuditRecord record) {
        record.ComputeDerivedMetrics();
        std::lock_guard<std::mutex> lock(mutex_);
        records_.push_back(std::move(record));
    }

    bool DumpToCsv(const std::string& filepath) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ofstream ofs(filepath);
        if (!ofs.is_open()) return false;

        // Write CSV standard header
        ofs << "test_id,protocol,subscriber_count,active_sessions,session_setup_rate_cps,"
            << "session_failure_rate_pct,packets_per_second,rx_drops,tx_errors,"
            << "cpu_utilization_pct,memory_usage_mb,test_duration_s,hardware_spec\n";

        for (const auto& rec : records_) {
            ofs << rec.ToCsvRow() << "\n";
        }
        return true;
    }

    bool DumpToJson(const std::string& filepath) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ofstream ofs(filepath);
        if (!ofs.is_open()) return false;

        auto root = samurai::core::json::Value::Object();
        auto arr = samurai::core::json::Value::Array();
        for (const auto& rec : records_) {
            arr.push_back(rec.ToJson());
        }
        root.set("records", std::move(arr));
        ofs << root.dump();
        return true;
    }

    void PrintSummary(const TelcoAuditRecord& record) const {
        std::cout << "\n=================================================================\n";
        std::cout << "          TELECOM ENGINE TELEMETRY AUDIT REPORT                  \n";
        std::cout << "=================================================================\n";
        std::cout << " Test ID           : " << record.test_id << "\n";
        std::cout << " Protocol          : " << record.protocol << "\n";
        std::cout << " Subscribers       : " << record.subscriber_count 
                  << " (Active: " << record.active_sessions << ")\n";
        std::cout << " Setup Rate (CPS)  : " << std::fixed << std::setprecision(1) 
                  << record.session_setup_rate_cps << " CPS\n";
        std::cout << " Failure Rate      : " << std::fixed << std::setprecision(3) 
                  << record.session_failure_rate_pct << " %\n";
        std::cout << " Throughput        : " << record.packets_per_second << " PPS"
                  << " (" << std::fixed << std::setprecision(2) << record.throughput_mbps << " Mbps)\n";
        std::cout << " Drops / Errors    : RX Drops: " << record.rx_drops 
                  << " | TX Errors: " << record.tx_errors << "\n";
        if (record.tx_frames > 0) {
            std::cout << " RFC 2544 Loss Rate: " << std::fixed << std::setprecision(3) 
                      << record.frame_loss_pct << " %\n";
            std::cout << " Latency (us)      : Min=" << record.min_latency_us 
                      << " | Avg=" << record.avg_latency_us 
                      << " | P99=" << record.p99_latency_us 
                      << " | Max=" << record.max_latency_us << "\n";
        }
        std::cout << " System Footprint  : CPU=" << record.cpu_utilization_pct << "%"
                  << " | RAM=" << record.memory_usage_mb << " MB\n";
        std::cout << " Test Duration     : " << record.test_duration_s << " s\n";
        std::cout << " Hardware Spec     : " << record.hardware_spec << "\n";
        std::cout << "-----------------------------------------------------------------\n";
        std::cout << " [HONESTY NOTICE] Verified on user-space software harness.\n";
        std::cout << "                 Physical 100G line rate verification requires\n";
        std::cout << "                 dedicated NICs (Intel i40e / Mellanox mlx5) and\n";
        std::cout << "                 RFC 2544 hardware bench fixtures.\n";
        std::cout << "=================================================================\n" << std::endl;
    }

    std::vector<TelcoAuditRecord> GetRecords() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return records_;
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        records_.clear();
    }

private:
    TelecomAuditLogger() = default;
    mutable std::mutex mutex_;
    std::vector<TelcoAuditRecord> records_;
};

} // namespace ddos_samurai::telecom
