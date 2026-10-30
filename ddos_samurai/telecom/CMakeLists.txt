cmake_minimum_required(VERSION 3.16)
project(samurai_telecom LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)

set(SAMURAI_TELECOM_SOURCES
  lockfree_l2l3_cache.hpp
  l2l3_fastpath_wiring.hpp
  l2l3_fastpath_wiring.cpp
  core/session_context.hpp
  core/telco_protocol_if.hpp
  core/session_manager.hpp
  core/session_manager.cpp
  core/hierarchical_timing_wheel.hpp
  core/hierarchical_timing_wheel.cpp
  core/fastpath_classifier.hpp
  core/fastpath_classifier.cpp
  core/ring_buffer_shuttle.hpp
  core/telecom_audit_logger.hpp
  protocols/stateful/pppoe/pppoe_types.hpp
  protocols/stateful/pppoe/pppoe_fsm.hpp
  protocols/stateful/pppoe/pppoe_engine.hpp
  protocols/stateful/pppoe/pppoe_engine.cpp
  protocols/stateful/dhcp/dhcp_types.hpp
  protocols/stateful/dhcp/dhcp_fsm.hpp
  protocols/stateful/dhcp/dhcp_engine.hpp
  protocols/stateful/dhcp/dhcp_engine.cpp
  protocols/stateful/bfd/bfd_types.hpp
  protocols/stateful/bfd/bfd_fsm.hpp
  protocols/stateful/bfd/bfd_engine.hpp
  protocols/stateful/bfd/bfd_engine.cpp
  protocols/stateful/mobile/gtpu_types.hpp
  protocols/stateful/mobile/gtpu_engine.hpp
  protocols/stateful/mobile/gtpu_engine.cpp
  protocols/stateful/mobile/pfcp_types.hpp
  protocols/stateful/mobile/pfcp_engine.hpp
  protocols/stateful/mobile/pfcp_engine.cpp
  protocols/stateless/gtpu_gen/gtpu_gen_types.hpp
  protocols/stateless/gtpu_gen/stateless_gtpu_generator.hpp
  protocols/stateless/gtpu_gen/stateless_gtpu_generator.cpp
  protocols/stateless/qinq_sweep/qinq_types.hpp
  protocols/stateless/qinq_sweep/qinq_generator.hpp
  protocols/stateless/qinq_sweep/qinq_generator.cpp
  protocols/stateless/arp_gen/arp_gen_types.hpp
  protocols/stateless/arp_gen/stateless_arp_generator.hpp
  protocols/stateless/arp_gen/stateless_arp_generator.cpp
  protocols/stateful/sctp/sctp_types.hpp
  protocols/stateful/sctp/sctp_engine.hpp
  protocols/stateful/sctp/sctp_engine.cpp
  protocols/stateful/diameter/diameter_types.hpp
  protocols/stateful/diameter/diameter_dictionary.hpp
  protocols/stateful/diameter/diameter_dictionary.cpp
  protocols/stateful/diameter/diameter_engine.hpp
  protocols/stateful/diameter/diameter_engine.cpp
  protocols/stateful/sip_rtp/sip_rtp_types.hpp
  protocols/stateful/sip_rtp/sip_rtp_engine.hpp
  protocols/stateful/sip_rtp/sip_rtp_engine.cpp
  protocols/stateful/sip_rtp/sip_digest_auth.hpp
  protocols/stateful/sip_rtp/sip_digest_auth.cpp
  protocols/stateful/sip_rtp/srtp_engine.hpp
  protocols/stateful/sip_rtp/srtp_engine.cpp
)

add_library(samurai_telecom_static STATIC ${SAMURAI_TELECOM_SOURCES})

target_include_directories(samurai_telecom_static PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/pppoe
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/dhcp
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/bfd
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/mobile
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/sctp
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/diameter
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/sip_rtp
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateless/gtpu_gen
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateless/qinq_sweep
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateless/arp_gen
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
  ${CMAKE_CURRENT_SOURCE_DIR}/../dpdk
)

target_compile_options(samurai_telecom_static PUBLIC -msse4.2)
target_link_libraries(samurai_telecom_static PUBLIC samurai_l7emu samurai_core pthread dl OpenSSL::Crypto)

# ---------------------------------------------------------------------------
# Unit Test Executables
# ---------------------------------------------------------------------------

add_executable(test_telco_core tests/test_telco_core.cpp)
target_include_directories(test_telco_core PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_telco_core PRIVATE -UNDEBUG)
target_link_libraries(test_telco_core PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_pppoe_fsm tests/test_pppoe_fsm.cpp)
target_include_directories(test_pppoe_fsm PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/pppoe
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_pppoe_fsm PRIVATE -UNDEBUG)
target_link_libraries(test_pppoe_fsm PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_dhcp_bfd tests/test_dhcp_bfd.cpp)
target_include_directories(test_dhcp_bfd PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/dhcp
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/bfd
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_dhcp_bfd PRIVATE -UNDEBUG)
target_link_libraries(test_dhcp_bfd PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_mobile_core tests/test_mobile_core.cpp)
target_include_directories(test_mobile_core PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/mobile
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_mobile_core PRIVATE -UNDEBUG)
target_link_libraries(test_mobile_core PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_stateless_generators tests/test_stateless_generators.cpp)
target_include_directories(test_stateless_generators PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateless/gtpu_gen
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateless/qinq_sweep
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateless/arp_gen
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_stateless_generators PRIVATE -UNDEBUG)
target_link_libraries(test_stateless_generators PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_multi_worker_telco tests/test_multi_worker_telco.cpp)
target_include_directories(test_multi_worker_telco PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/pppoe
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_multi_worker_telco PRIVATE -msse4.2 -UNDEBUG)
target_link_libraries(test_multi_worker_telco PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_telco_cluster_sharding tests/test_telco_cluster_sharding.cpp)
target_include_directories(test_telco_cluster_sharding PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/../control
  ${CMAKE_CURRENT_SOURCE_DIR}/../core
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_telco_cluster_sharding PRIVATE -msse4.2 -UNDEBUG)
target_link_libraries(test_telco_cluster_sharding PRIVATE samurai_control samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_telco_chaos_recovery tests/test_telco_chaos_recovery.cpp)
target_include_directories(test_telco_chaos_recovery PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/pppoe
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/dhcp
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_telco_chaos_recovery PRIVATE -msse4.2 -UNDEBUG)
target_link_libraries(test_telco_chaos_recovery PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_telco_audit_logger tests/test_telco_audit_logger.cpp)
target_include_directories(test_telco_audit_logger PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_telco_audit_logger PRIVATE -msse4.2 -UNDEBUG)
target_link_libraries(test_telco_audit_logger PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_sctp_engine tests/test_sctp_engine.cpp)
target_include_directories(test_sctp_engine PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/sctp
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_sctp_engine PRIVATE -msse4.2 -UNDEBUG)
target_link_libraries(test_sctp_engine PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_diameter_engine tests/test_diameter_engine.cpp)
target_include_directories(test_diameter_engine PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/diameter
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_diameter_engine PRIVATE -msse4.2 -UNDEBUG)
target_link_libraries(test_diameter_engine PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_sip_rtp_engine tests/test_sip_rtp_engine.cpp)
target_include_directories(test_sip_rtp_engine PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/sip_rtp
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_sip_rtp_engine PRIVATE -msse4.2 -UNDEBUG)
target_link_libraries(test_sip_rtp_engine PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_upstream_telco_integration
  tests/test_upstream_telco_integration.cpp
  ../cli/args.cpp
  ../cli/profiles.cpp
)
target_include_directories(test_upstream_telco_integration PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/sctp
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/diameter
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/sip_rtp
  ${CMAKE_CURRENT_SOURCE_DIR}/../cli
  ${CMAKE_CURRENT_SOURCE_DIR}/../orchestrator
  ${CMAKE_CURRENT_SOURCE_DIR}/../zmq/daemon
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_upstream_telco_integration PRIVATE -msse4.2 -UNDEBUG)
target_link_libraries(test_upstream_telco_integration PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

# ---------------------------------------------------------------------------
# CTest Registrations for Automated CI/CD
# ---------------------------------------------------------------------------
add_test(NAME telecom_core COMMAND test_telco_core)
add_test(NAME telecom_pppoe_fsm COMMAND test_pppoe_fsm)
add_test(NAME telecom_dhcp_bfd COMMAND test_dhcp_bfd)
add_test(NAME telecom_mobile_core COMMAND test_mobile_core)
add_test(NAME telecom_stateless_generators COMMAND test_stateless_generators)
add_test(NAME telecom_multi_worker_telco COMMAND test_multi_worker_telco)
add_test(NAME telecom_cluster_sharding COMMAND test_telco_cluster_sharding)
add_test(NAME telecom_chaos_recovery COMMAND test_telco_chaos_recovery)
add_test(NAME telecom_audit_logger COMMAND test_telco_audit_logger)
add_test(NAME telecom_sctp COMMAND test_sctp_engine)
add_test(NAME telecom_diameter COMMAND test_diameter_engine)
add_test(NAME telecom_sip_rtp COMMAND test_sip_rtp_engine)
add_test(NAME telecom_upstream_integration COMMAND test_upstream_telco_integration)

