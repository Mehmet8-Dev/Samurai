#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

uint16_t samurai_dpdk_rx_burst(uint16_t port_id, uint16_t queue_id, void** rx_mbufs, uint16_t nb_pkts);
uint16_t samurai_dpdk_tx_burst(uint16_t port_id, uint16_t queue_id, void** tx_mbufs, uint16_t nb_pkts);
void* samurai_dpdk_get_mempool(uint16_t port_id);

#ifdef __cplusplus
}
#endif

