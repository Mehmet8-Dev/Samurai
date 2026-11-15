cmake_minimum_required(VERSION 3.16)
project(samurai_telecom LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  set(SAMURAI_ARCH_FLAGS "-msse4.2")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  set(SAMURAI_ARCH_FLAGS "-march=armv8-a+crc")
else()
  set(SAMURAI_ARCH_FLAGS "")
endif()

find_package(OpenSSL REQUIRED)

set(SAMURAI_TELECOM_SOURCES
  lockfree_l2l3_cache.hpp
  l2l3_fastpath_wiring.hpp
  l2l3_fastpath_wiring.cpp
  core/session_context.hpp
  core/telco_protocol_if.hpp
  core/telco_packet_transport.hpp
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
  cups/dpu_arm_cups_bridge.hpp
  cups/dpu_arm_cups_bridge.cpp
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
  ${CMAKE_CURRENT_SOURCE_DIR}/cups
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
  ${CMAKE_CURRENT_SOURCE_DIR}/../dpdk
)

if(SAMURAI_ARCH_FLAGS)
  target_compile_options(samurai_telecom_static PUBLIC ${SAMURAI_ARCH_FLAGS})
endif()
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
target_compile_options(test_multi_worker_telco PRIVATE ${SAMURAI_ARCH_FLAGS} -UNDEBUG)
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
target_compile_options(test_telco_cluster_sharding PRIVATE ${SAMURAI_ARCH_FLAGS} -UNDEBUG)
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
target_compile_options(test_telco_chaos_recovery PRIVATE ${SAMURAI_ARCH_FLAGS} -UNDEBUG)
target_link_libraries(test_telco_chaos_recovery PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_telco_audit_logger tests/test_telco_audit_logger.cpp)
target_include_directories(test_telco_audit_logger PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_telco_audit_logger PRIVATE ${SAMURAI_ARCH_FLAGS} -UNDEBUG)
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
target_compile_options(test_sctp_engine PRIVATE ${SAMURAI_ARCH_FLAGS} -UNDEBUG)
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
target_compile_options(test_diameter_engine PRIVATE ${SAMURAI_ARCH_FLAGS} -UNDEBUG)
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
target_compile_options(test_sip_rtp_engine PRIVATE ${SAMURAI_ARCH_FLAGS} -UNDEBUG)
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
target_compile_options(test_upstream_telco_integration PRIVATE ${SAMURAI_ARCH_FLAGS} -UNDEBUG)
target_link_libraries(test_upstream_telco_integration PRIVATE samurai_telecom_static samurai_l7emu samurai_core pthread)

add_executable(test_gpu_worker_telecom_zmq tests/test_gpu_worker_telecom_zmq.cpp)
target_include_directories(test_gpu_worker_telecom_zmq PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_SOURCE_DIR}/core
  ${CMAKE_CURRENT_SOURCE_DIR}/../zmq/daemon
  ${CMAKE_CURRENT_SOURCE_DIR}/../zmq/lib
  ${CMAKE_CURRENT_SOURCE_DIR}/../core
  ${CMAKE_CURRENT_SOURCE_DIR}/../cpu_native
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
)
target_compile_options(test_gpu_worker_telecom_zmq PRIVATE -UNDEBUG)
target_link_libraries(test_gpu_worker_telecom_zmq PRIVATE samurai_core samurai_telecom_static samurai_l7emu zmq pthread dl OpenSSL::Crypto)

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
add_test(NAME telecom_gpu_worker_zmq COMMAND test_gpu_worker_telecom_zmq)
set_tests_properties(telecom_gpu_worker_zmq PROPERTIES
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/.."
  ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_SOURCE_DIR}/..:${CMAKE_SOURCE_DIR}/../samurai:$ENV{LD_LIBRARY_PATH}"
)

find_program(SAMURAI_NVCC nvcc HINTS ENV SAMURAI_NVCC /usr/local/cuda/bin)
if(SAMURAI_NVCC)
  set(TEST_GPU_DOORBELL_BIN ${CMAKE_CURRENT_BINARY_DIR}/test_gpu_doorbell_hardening)
  add_custom_command(
    OUTPUT ${TEST_GPU_DOORBELL_BIN}
    COMMAND ${SAMURAI_NVCC} -std=c++20 -O2
            -I ${CMAKE_CURRENT_SOURCE_DIR}/../..
            -I ${CMAKE_CURRENT_SOURCE_DIR}/..
            -I ${CMAKE_CURRENT_SOURCE_DIR}
            -I ${CMAKE_CURRENT_SOURCE_DIR}/../core
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gpu_doorbell_hardening.cu
            -o ${TEST_GPU_DOORBELL_BIN}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gpu_doorbell_hardening.cu
            ${CMAKE_CURRENT_SOURCE_DIR}/../gpu_packet_cuda/gpu_initiated_doorbell.cuh
            ${CMAKE_CURRENT_SOURCE_DIR}/../gpu_packet_cuda/geforce_p2p_runtime.cuh
    COMMENT "Compiling test_gpu_doorbell_hardening with nvcc"
    VERBATIM
  )
  add_custom_target(build_test_gpu_doorbell_hardening ALL DEPENDS ${TEST_GPU_DOORBELL_BIN})
  add_test(NAME telecom_gpu_doorbell_hardening COMMAND ${TEST_GPU_DOORBELL_BIN})
  set_tests_properties(telecom_gpu_doorbell_hardening PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/.."
  )

  set(TEST_GPU_TELECOM_KERNELS_BIN ${CMAKE_CURRENT_BINARY_DIR}/test_gpu_telecom_kernels)
  add_custom_command(
    OUTPUT ${TEST_GPU_TELECOM_KERNELS_BIN}
    COMMAND ${SAMURAI_NVCC} -std=c++20 -O2
            -I ${CMAKE_CURRENT_SOURCE_DIR}/../..
            -I ${CMAKE_CURRENT_SOURCE_DIR}/..
            -I ${CMAKE_CURRENT_SOURCE_DIR}
            -I ${CMAKE_CURRENT_SOURCE_DIR}/../core
            -I ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gpu_telecom_kernels.cu
            ${CMAKE_CURRENT_SOURCE_DIR}/../libgpu_packet_cuda.so
            $<TARGET_FILE:samurai_core>
            $<TARGET_FILE:samurai_telecom_static>
            $<TARGET_FILE:samurai_l7emu>
            -lcrypto -ldl
            -o ${TEST_GPU_TELECOM_KERNELS_BIN}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gpu_telecom_kernels.cu
            ${CMAKE_CURRENT_SOURCE_DIR}/../gpu_packet_cuda/kernels_telecom.cuh
            ${CMAKE_CURRENT_SOURCE_DIR}/../gpu_packet_cuda/zero_copy_dataplane_contract.cuh
            ${CMAKE_CURRENT_SOURCE_DIR}/../libgpu_packet_cuda.so
            samurai_core samurai_telecom_static samurai_l7emu
    COMMENT "Compiling test_gpu_telecom_kernels with nvcc"
    VERBATIM
  )
  add_custom_target(build_test_gpu_telecom_kernels ALL DEPENDS ${TEST_GPU_TELECOM_KERNELS_BIN})
  add_test(NAME telecom_gpu_kernels COMMAND ${TEST_GPU_TELECOM_KERNELS_BIN})
  set_tests_properties(telecom_gpu_kernels PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/.."
    ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_SOURCE_DIR}/..:${CMAKE_SOURCE_DIR}/../samurai:$ENV{LD_LIBRARY_PATH}"
  )

  set(TEST_DPU_ARM_CUPS_GPU_BRIDGE_BIN ${CMAKE_CURRENT_BINARY_DIR}/test_dpu_arm_cups_gpu_bridge)
  add_custom_command(
    OUTPUT ${TEST_DPU_ARM_CUPS_GPU_BRIDGE_BIN}
    COMMAND ${SAMURAI_NVCC} -std=c++20 -O2
            -I ${CMAKE_CURRENT_SOURCE_DIR}/../..
            -I ${CMAKE_CURRENT_SOURCE_DIR}/..
            -I ${CMAKE_CURRENT_SOURCE_DIR}
            -I ${CMAKE_CURRENT_SOURCE_DIR}/core
            -I ${CMAKE_CURRENT_SOURCE_DIR}/cups
            -I ${CMAKE_CURRENT_SOURCE_DIR}/protocols/stateful/mobile
            -I ${CMAKE_CURRENT_SOURCE_DIR}/../core
            -I ${CMAKE_CURRENT_SOURCE_DIR}/../zmq/daemon
            -I ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_dpu_arm_cups_gpu_bridge.cu
            ${CMAKE_CURRENT_SOURCE_DIR}/../libgpu_packet_cuda.so
            $<TARGET_FILE:samurai_telecom_static>
            $<TARGET_FILE:samurai_core>
            $<TARGET_FILE:samurai_l7emu>
            -lcrypto -ldl
            -o ${TEST_DPU_ARM_CUPS_GPU_BRIDGE_BIN}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_dpu_arm_cups_gpu_bridge.cu
            ${CMAKE_CURRENT_SOURCE_DIR}/cups/dpu_arm_cups_bridge.hpp
            ${CMAKE_CURRENT_SOURCE_DIR}/cups/dpu_arm_cups_bridge.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../libgpu_packet_cuda.so
            samurai_telecom_static samurai_core samurai_l7emu
    COMMENT "Compiling test_dpu_arm_cups_gpu_bridge with nvcc"
    VERBATIM
  )
  add_custom_target(build_test_dpu_arm_cups_gpu_bridge ALL DEPENDS ${TEST_DPU_ARM_CUPS_GPU_BRIDGE_BIN})
  add_test(NAME telecom_dpu_arm_cups_gpu_bridge COMMAND ${TEST_DPU_ARM_CUPS_GPU_BRIDGE_BIN})
  set_tests_properties(telecom_dpu_arm_cups_gpu_bridge PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/.."
    ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_SOURCE_DIR}/..:${CMAKE_SOURCE_DIR}/../samurai:$ENV{LD_LIBRARY_PATH}"
  )
endif()

