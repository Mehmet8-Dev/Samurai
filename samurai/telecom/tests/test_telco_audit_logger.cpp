#include <cassert>
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>
#include <cstdio>

#include "telecom_audit_logger.hpp"

using namespace samurai::telecom;

void TestTelcoAuditRecord_DerivedMetrics() {
    std::cout << "[TEST] TelcoAuditRecord Derived Metrics..." << std::endl;

    TelcoAuditRecord rec;
    rec.test_id = "AUDIT-001";
    rec.protocol = "PPPOE";
    rec.subscriber_count = 10000;
    rec.active_sessions = 9500;
    rec.test_duration_s = 10.0;
    rec.tx_frames = 100000;
    rec.rx_frames = 98000;

    rec.ComputeDerivedMetrics();

    // 500 failed out of 10000 -> 5.0%
    assert(std::abs(rec.session_failure_rate_pct - 5.0) < 0.001);
    // 9500 sessions in 10s -> 950.0 CPS
    assert(std::abs(rec.session_setup_rate_cps - 950.0) < 0.001);
    // 2000 dropped out of 100000 -> 2.0%
    assert(std::abs(rec.frame_loss_pct - 2.0) < 0.001);
    // 100000 tx frames in 10s -> 10000 PPS
    assert(rec.packets_per_second == 10000);

    std::cout << "  ✓ Derived metrics computed with exact mathematical precision" << std::endl;
}

void TestTelcoAuditLogger_CsvDump() {
    std::cout << "[TEST] TelcoAuditLogger CSV Dump & Verification..." << std::endl;

    auto& logger = TelecomAuditLogger::Instance();
    logger.Clear();

    TelcoAuditRecord r1;
    r1.test_id = "RFC2544-PPPOE-01";
    r1.protocol = "PPPOE";
    r1.subscriber_count = 50000;
    r1.active_sessions = 50000;
    r1.test_duration_s = 5.0;
    r1.tx_frames = 500000;
    r1.rx_frames = 500000;
    r1.cpu_utilization_pct = 22.5;
    r1.memory_usage_mb = 128.0;

    TelcoAuditRecord r2;
    r2.test_id = "RFC2889-GTPU-02";
    r2.protocol = "GTPU";
    r2.subscriber_count = 20000;
    r2.active_sessions = 19000;
    r2.test_duration_s = 2.0;
    r2.tx_frames = 200000;
    r2.rx_frames = 190000;
    r2.cpu_utilization_pct = 45.0;
    r2.memory_usage_mb = 256.0;

    logger.Record(r1);
    logger.Record(r2);

    const std::string csv_path = "/tmp/test_telco_audit_export.csv";
    bool dump_ok = logger.DumpToCsv(csv_path);
    assert(dump_ok);

    // Read back CSV file
    std::ifstream ifs(csv_path);
    assert(ifs.is_open());
    std::string header;
    std::getline(ifs, header);
    assert(header.find("test_id,protocol,subscriber_count") != std::string::npos);

    std::string row1;
    std::getline(ifs, row1);
    assert(row1.find("RFC2544-PPPOE-01") != std::string::npos);
    assert(row1.find("PPPOE") != std::string::npos);

    std::string row2;
    std::getline(ifs, row2);
    assert(row2.find("RFC2889-GTPU-02") != std::string::npos);
    assert(row2.find("GTPU") != std::string::npos);

    ifs.close();
    std::remove(csv_path.c_str());

    std::cout << "  ✓ CSV export generated and verified successfully" << std::endl;
}

void TestTelcoAuditLogger_JsonDump() {
    std::cout << "[TEST] TelcoAuditLogger JSON Dump & Verification..." << std::endl;

    auto& logger = TelecomAuditLogger::Instance();
    logger.Clear();

    TelcoAuditRecord r;
    r.test_id = "RFC2544-DHCP-01";
    r.protocol = "DHCP";
    r.subscriber_count = 100000;
    r.active_sessions = 99800;
    r.test_duration_s = 10.0;
    r.tx_frames = 1000000;
    r.rx_frames = 998000;
    r.throughput_mbps = 942.50;
    r.min_latency_us = 12.4;
    r.avg_latency_us = 45.8;
    r.p99_latency_us = 120.3;
    r.max_latency_us = 350.0;
    r.cpu_utilization_pct = 38.2;
    r.memory_usage_mb = 512.0;

    logger.Record(r);

    const std::string json_path = "/tmp/test_telco_audit_export.json";
    bool dump_ok = logger.DumpToJson(json_path);
    assert(dump_ok);

    std::ifstream ifs(json_path);
    assert(ifs.is_open());
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string json_str = buffer.str();
    ifs.close();
    std::remove(json_path.c_str());

    auto parsed = samurai::core::json::Parse(json_str);
    assert(parsed.ok);
    assert(parsed.value.is_object());
    const auto* records_arr = parsed.value.find("records");
    assert(records_arr && records_arr->is_array());
    assert(records_arr->elements().size() == 1);

    const auto& rec_obj = records_arr->elements()[0];
    assert(rec_obj.find("test_id")->as_string() == "RFC2544-DHCP-01");
    assert(rec_obj.find("protocol")->as_string() == "DHCP");
    assert(rec_obj.find("subscriber_count")->as_int() == 100000);
    assert(rec_obj.find("active_sessions")->as_int() == 99800);

    const auto* rfc_obj = rec_obj.find("rfc2544");
    assert(rfc_obj && rfc_obj->is_object());
    assert(rfc_obj->find("tx_frames")->as_int() == 1000000);
    assert(rfc_obj->find("rx_frames")->as_int() == 998000);
    assert(std::abs(rfc_obj->find("avg_latency_us")->as_double() - 45.8) < 0.001);

    logger.PrintSummary(r);

    std::cout << "  ✓ JSON export and structured RFC 2544 fields verified successfully" << std::endl;
}

void TestTelcoAuditLogger_Concurrency() {
    std::cout << "[TEST] TelcoAuditLogger Thread Concurrency..." << std::endl;

    auto& logger = TelecomAuditLogger::Instance();
    logger.Clear();

    constexpr int NUM_THREADS = 8;
    constexpr int RECORDS_PER_THREAD = 100;
    std::vector<std::thread> workers;
    workers.reserve(NUM_THREADS);

    for (int t = 0; t < NUM_THREADS; ++t) {
        workers.emplace_back([t, &logger]() {
            for (int i = 0; i < RECORDS_PER_THREAD; ++i) {
                TelcoAuditRecord rec;
                rec.test_id = "THREAD-" + std::to_string(t) + "-REC-" + std::to_string(i);
                rec.protocol = (t % 2 == 0) ? "PPPOE" : "BFD";
                rec.subscriber_count = 1000;
                rec.active_sessions = 1000;
                rec.test_duration_s = 1.0;
                logger.Record(rec);
            }
        });
    }

    for (auto& w : workers) {
        w.join();
    }

    auto records = logger.GetRecords();
    assert(records.size() == NUM_THREADS * RECORDS_PER_THREAD);
    std::cout << "  ✓ Thread-safe concurrent logging verified with " 
              << records.size() << " total records" << std::endl;
}

int main() {
    std::cout << "=== Running Telecom Audit Logger Unit Tests ===" << std::endl;
    TestTelcoAuditRecord_DerivedMetrics();
    TestTelcoAuditLogger_CsvDump();
    TestTelcoAuditLogger_JsonDump();
    TestTelcoAuditLogger_Concurrency();
    std::cout << "=== All Telecom Audit Logger Tests Passed! ===" << std::endl;
    return 0;
}
