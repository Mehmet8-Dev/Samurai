cmake_minimum_required(VERSION 3.16)
project(samurai_telecom LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateless/gtpu_gen
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateless/qinq_sweep
  ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateless/arp_gen
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
  ${CMAKE_CURRENT_SOURCE_DIR}/../dpdk
)

target_compile_options(samurai_telecom_static PUBLIC -msse4.2)
target_link_libraries(samurai_telecom_static PUBLIC samurai_l7emu samurai_core pthread dl)

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
