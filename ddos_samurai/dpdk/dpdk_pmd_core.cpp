#include "dpdk_pmd_core.hpp"

#include <Python.h>

extern "C" {
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
}

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr uint16_t kMaxBurst = 1024;
constexpr uint16_t kMinBurst = 1;
constexpr uint32_t kDefaultMbufDataSize = RTE_MBUF_DEFAULT_BUF_SIZE;
constexpr uint32_t kDefaultMempoolCache = 256;

struct PortState {
    rte_mempool* mempool = nullptr;
    bool mempool_owned = false;
    int socket_id = 0;
    uint16_t tx_queues = 0;
    uint16_t rx_queues = 0;
    bool started = false;
    bool rx_enabled = false;
    uint32_t users = 0;
};

struct Context {
    uint16_t port_id = 0;
    uint16_t queue_id = 0;
    uint16_t burst_size = 64;
    uint32_t mempool_size = 8192;
    bool rx_enable = false;
    int socket_id = 0;

    std::atomic<uint64_t> tx_packets{0};
    std::atomic<uint64_t> tx_bytes{0};
    std::atomic<uint64_t> tx_errors{0};
    std::atomic<uint64_t> tx_dropped{0};
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> rx_bytes{0};
    std::atomic<uint64_t> rx_dropped{0};
    std::atomic<uint64_t> mbuf_alloc_failures{0};
};

std::mutex g_mu;
bool g_eal_initialized = false;
std::string g_locked_eal_args;
long g_next_handle = 1;
std::unordered_map<long, Context> g_contexts;
std::unordered_map<uint16_t, PortState> g_ports;

static inline int dict_int(PyObject* cfg, const char* key, int def) {
    if (!cfg || !PyDict_Check(cfg)) {
        return def;
    }
    PyObject* v = PyDict_GetItemString(cfg, key);
    if (!v) {
        return def;
    }
    long out = PyLong_AsLong(v);
    if (PyErr_Occurred()) {
        PyErr_Clear();
        return def;
    }
    return static_cast<int>(out);
}

static inline std::string dict_str(PyObject* cfg, const char* key, const char* def = "") {
    if (!cfg || !PyDict_Check(cfg)) {
        return std::string(def ? def : "");
    }
    PyObject* v = PyDict_GetItemString(cfg, key);
    if (!v) {
        return std::string(def ? def : "");
    }
    PyObject* s = PyObject_Str(v);
    if (!s) {
        PyErr_Clear();
        return std::string(def ? def : "");
    }
    const char* c = PyUnicode_AsUTF8(s);
    std::string out = c ? std::string(c) : std::string(def ? def : "");
    Py_DECREF(s);
    return out;
}

static inline bool dict_bool(PyObject* cfg, const char* key, bool def = false) {
    int d = def ? 1 : 0;
    return dict_int(cfg, key, d) != 0;
}

static std::vector<std::string> split_ws(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream iss(text);
    std::string token;
    while (iss >> token) {
        if (!token.empty()) {
            out.push_back(token);
        }
    }
    return out;
}

static bool ensure_eal_locked(const std::string& eal_args, std::string& err) {
    if (!g_eal_initialized) {
        std::vector<std::string> argv_store;
        argv_store.emplace_back("ddos_samurai_dpdk");
        auto extra = split_ws(eal_args);
        argv_store.insert(argv_store.end(), extra.begin(), extra.end());

        std::vector<char*> argv;
        argv.reserve(argv_store.size());
        for (auto& s : argv_store) {
            argv.push_back(const_cast<char*>(s.c_str()));
        }

        int rc = rte_eal_init(static_cast<int>(argv.size()), argv.data());
        if (rc < 0) {
            err = std::string("dpdk_eal_init_failed:") + rte_strerror(rte_errno);
            return false;
        }
        g_eal_initialized = true;
        g_locked_eal_args = eal_args;
        return true;
    }

    if (g_locked_eal_args != eal_args) {
        err = "dpdk_eal_duplicate_init";
        return false;
    }
    return true;
}

static void teardown_port_unlocked(uint16_t port_id, PortState& st) {
    if (st.started) {
        (void)rte_eth_dev_stop(port_id);
    }
    (void)rte_eth_dev_close(port_id);
    if (st.mempool && st.mempool_owned) {
        rte_mempool_free(st.mempool);
    }
    st.mempool = nullptr;
    st.mempool_owned = false;
    st.started = false;
    st.rx_enabled = false;
    st.tx_queues = 0;
    st.rx_queues = 0;
}

static bool ensure_port_ready(
    uint16_t port_id,
    uint16_t queue_id,
    bool rx_enable,
    uint32_t mempool_size,
    PortState& out,
    std::string& err
) {
    if (!rte_eth_dev_is_valid_port(port_id)) {
        err = "dpdk_port_invalid";
        return false;
    }

    auto it = g_ports.find(port_id);
    if (it != g_ports.end() && it->second.started) {
        if (queue_id >= it->second.tx_queues) {
            err = "dpdk_queue_unavailable";
            return false;
        }
        if (rx_enable && !it->second.rx_enabled) {
            err = "dpdk_rx_not_configured";
            return false;
        }
        out = it->second;
        return true;
    }

    rte_eth_dev_info dev_info;
    std::memset(&dev_info, 0, sizeof(dev_info));
    if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
        err = "dpdk_dev_info_failed";
        return false;
    }

    const uint16_t txq = static_cast<uint16_t>(queue_id + 1);
    const uint16_t rxq = rx_enable ? static_cast<uint16_t>(queue_id + 1) : 0;

    rte_eth_conf port_conf;
    std::memset(&port_conf, 0, sizeof(port_conf));

    if (rte_eth_dev_configure(port_id, rxq, txq, &port_conf) < 0) {
        err = std::string("dpdk_dev_configure_failed:") + rte_strerror(rte_errno);
        return false;
    }

    int socket_id = rte_eth_dev_socket_id(port_id);
    if (socket_id < 0) {
        socket_id = 0;
    }

    char mp_name[64];
    std::snprintf(mp_name, sizeof(mp_name), "samurai_dpdk_mp_%u", static_cast<unsigned>(port_id));

    rte_mempool* mp = rte_mempool_lookup(mp_name);
    bool mp_owned = false;
    if (!mp) {
        const uint32_t cache_sz = std::min<uint32_t>(kDefaultMempoolCache, std::max<uint32_t>(1u, mempool_size / 8u));
        mp = rte_pktmbuf_pool_create(
            mp_name,
            mempool_size,
            cache_sz,
            0,
            kDefaultMbufDataSize,
            socket_id
        );
        mp_owned = (mp != nullptr);
    }
    if (!mp) {
        err = std::string("dpdk_mempool_create_failed:") + rte_strerror(rte_errno);
        return false;
    }

    rte_eth_txconf tx_conf = dev_info.default_txconf;
    for (uint16_t q = 0; q < txq; ++q) {
        if (rte_eth_tx_queue_setup(port_id, q, 1024, socket_id, &tx_conf) < 0) {
            err = std::string("dpdk_tx_queue_setup_failed:") + rte_strerror(rte_errno);
            PortState cleanup;
            cleanup.mempool = mp;
            cleanup.mempool_owned = mp_owned;
            teardown_port_unlocked(port_id, cleanup);
            return false;
        }
    }

    if (rx_enable) {
        rte_eth_rxconf rx_conf = dev_info.default_rxconf;
        for (uint16_t q = 0; q < rxq; ++q) {
            if (rte_eth_rx_queue_setup(port_id, q, 1024, socket_id, &rx_conf, mp) < 0) {
                err = std::string("dpdk_rx_queue_setup_failed:") + rte_strerror(rte_errno);
                PortState cleanup;
                cleanup.mempool = mp;
                cleanup.mempool_owned = mp_owned;
                teardown_port_unlocked(port_id, cleanup);
                return false;
            }
        }
    }

    if (rte_eth_dev_start(port_id) < 0) {
        err = std::string("dpdk_dev_start_failed:") + rte_strerror(rte_errno);
        PortState cleanup;
        cleanup.mempool = mp;
        cleanup.mempool_owned = mp_owned;
        teardown_port_unlocked(port_id, cleanup);
        return false;
    }

    PortState st;
    st.mempool = mp;
    st.mempool_owned = mp_owned;
    st.socket_id = socket_id;
    st.tx_queues = txq;
    st.rx_queues = rxq;
    st.started = true;
    st.rx_enabled = rx_enable;
    st.users = 0;

    g_ports[port_id] = st;
    out = st;
    return true;
}

static PyObject* make_availability(
    bool available,
    const std::string& error = "",
    uint16_t port_count = 0
) {
    return Py_BuildValue(
        "{s:i,s:s,s:i,s:s,s:i}",
        "available", available ? 1 : 0,
        "module", "ddos_samurai.dpdk_pmd_core",
        "native", 1,
        "error", error.c_str(),
        "port_count", static_cast<int>(port_count)
    );
}

static PyObject* py_dpdk_available(PyObject*, PyObject*) {
    std::lock_guard<std::mutex> lock(g_mu);

    std::string eal_args;
    if (const char* env_args = std::getenv("SAMURAI_DPDK_EAL_ARGS")) {
        eal_args = env_args;
    }

    std::string err;
    if (!ensure_eal_locked(eal_args, err)) {
        return make_availability(false, err, 0);
    }

    const uint16_t port_count = static_cast<uint16_t>(rte_eth_dev_count_avail());
    if (port_count == 0) {
        return make_availability(false, "dpdk_no_ethdev", 0);
    }

    return make_availability(true, "", port_count);
}

static PyObject* py_dpdk_open(PyObject*, PyObject* args) {
    PyObject* cfg = nullptr;
    if (!PyArg_ParseTuple(args, "O", &cfg) || !PyDict_Check(cfg)) {
        PyErr_SetString(PyExc_TypeError, "dpdk_open expects config dict");
        return nullptr;
    }

    if (!dict_bool(cfg, "enable", false)) {
        PyErr_SetString(PyExc_RuntimeError, "dpdk_not_enabled");
        return nullptr;
    }

    const uint16_t port_id = static_cast<uint16_t>(std::max(0, dict_int(cfg, "port_id", 0)));
    const uint16_t queue_id = static_cast<uint16_t>(std::max(0, dict_int(cfg, "queue_id", 0)));
    const uint16_t burst_size = static_cast<uint16_t>(std::clamp(dict_int(cfg, "burst_size", 64), static_cast<int>(kMinBurst), static_cast<int>(kMaxBurst)));
    const uint32_t mempool_size = static_cast<uint32_t>(std::max(128, dict_int(cfg, "mempool_size", 8192)));
    const bool rx_enable = dict_bool(cfg, "rx_enable", false);
    const std::string eal_args = dict_str(cfg, "eal_args", "");

    std::lock_guard<std::mutex> lock(g_mu);

    std::string err;
    if (!ensure_eal_locked(eal_args, err)) {
        PyErr_SetString(PyExc_RuntimeError, err.c_str());
        return nullptr;
    }

    PortState st;
    if (!ensure_port_ready(port_id, queue_id, rx_enable, mempool_size, st, err)) {
        PyErr_SetString(PyExc_RuntimeError, err.c_str());
        return nullptr;
    }

    Context ctx;
    ctx.port_id = port_id;
    ctx.queue_id = queue_id;
    ctx.burst_size = burst_size;
    ctx.mempool_size = mempool_size;
    ctx.rx_enable = rx_enable;
    ctx.socket_id = st.socket_id;

    const long handle = g_next_handle++;
    g_contexts.emplace(handle, std::move(ctx));
    g_ports[port_id].users += 1;

    return PyLong_FromLong(handle);
}

static PyObject* py_dpdk_send_batch(PyObject*, PyObject* args) {
    long handle = 0;
    PyObject* buffer_obj = nullptr;
    int packet_size_i = 0;
    int count_i = 0;
    if (!PyArg_ParseTuple(args, "lOii", &handle, &buffer_obj, &packet_size_i, &count_i)) {
        return nullptr;
    }

    if (packet_size_i <= 0 || count_i < 0) {
        PyErr_SetString(PyExc_ValueError, "invalid packet_size/count");
        return nullptr;
    }
    const uint16_t packet_size = static_cast<uint16_t>(packet_size_i);
    uint64_t requested = static_cast<uint64_t>(count_i);

    Py_buffer view;
    std::memset(&view, 0, sizeof(view));
    if (PyObject_GetBuffer(buffer_obj, &view, PyBUF_SIMPLE) != 0) {
        return nullptr;
    }

    const uint64_t needed = requested * static_cast<uint64_t>(packet_size);
    if (static_cast<uint64_t>(view.len) < needed) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "buffer too small for requested packet batch");
        return nullptr;
    }

    uint16_t port_id = 0;
    uint16_t queue_id = 0;
    uint16_t burst_size = 64;
    rte_mempool* mempool = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_contexts.find(handle);
        if (it == g_contexts.end()) {
            PyBuffer_Release(&view);
            PyErr_SetString(PyExc_RuntimeError, "dpdk_invalid_handle");
            return nullptr;
        }
        port_id = it->second.port_id;
        queue_id = it->second.queue_id;
        burst_size = it->second.burst_size;
        auto pt = g_ports.find(port_id);
        if (pt == g_ports.end() || !pt->second.mempool) {
            PyBuffer_Release(&view);
            PyErr_SetString(PyExc_RuntimeError, "dpdk_port_not_ready");
            return nullptr;
        }
        mempool = pt->second.mempool;
    }

    uint64_t sent_total = 0;
    uint64_t dropped_total = 0;
    uint64_t alloc_fail_total = 0;
    uint64_t error_total = 0;

    auto* base = static_cast<const uint8_t*>(view.buf);

    Py_BEGIN_ALLOW_THREADS
    while (sent_total + dropped_total < requested) {
        const uint64_t left = requested - sent_total - dropped_total;
        const uint16_t batch = static_cast<uint16_t>(std::min<uint64_t>(burst_size, left));

        rte_mbuf* mbufs[kMaxBurst];
        if (rte_pktmbuf_alloc_bulk(mempool, mbufs, batch) != 0) {
            alloc_fail_total += batch;
            error_total += batch;
            dropped_total += batch;
            continue;
        }

        const uint64_t start_idx = sent_total + dropped_total;
        for (uint16_t i = 0; i < batch; ++i) {
            const uint8_t* src = base + ((start_idx + i) * static_cast<uint64_t>(packet_size));
            uint8_t* dst = rte_pktmbuf_mtod(mbufs[i], uint8_t*);
            std::memcpy(dst, src, packet_size);
            mbufs[i]->data_len = packet_size;
            mbufs[i]->pkt_len = packet_size;
        }

        uint16_t offset = 0;
        uint16_t remaining = batch;
        int retry = 0;
        while (remaining > 0 && retry < 8) {
            const uint16_t n = rte_eth_tx_burst(port_id, queue_id, &mbufs[offset], remaining);
            offset += n;
            remaining = static_cast<uint16_t>(remaining - n);
            if (remaining > 0) {
                ++retry;
                rte_pause();
            }
        }

        sent_total += offset;
        if (remaining > 0) {
            for (uint16_t i = 0; i < remaining; ++i) {
                rte_pktmbuf_free(mbufs[offset + i]);
            }
            dropped_total += remaining;
            error_total += remaining;
        }
    }
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&view);

    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_contexts.find(handle);
        if (it != g_contexts.end()) {
            it->second.tx_packets.fetch_add(sent_total, std::memory_order_relaxed);
            it->second.tx_bytes.fetch_add(sent_total * static_cast<uint64_t>(packet_size), std::memory_order_relaxed);
            it->second.tx_errors.fetch_add(error_total, std::memory_order_relaxed);
            it->second.tx_dropped.fetch_add(dropped_total, std::memory_order_relaxed);
            it->second.mbuf_alloc_failures.fetch_add(alloc_fail_total, std::memory_order_relaxed);
        }
    }

    return Py_BuildValue(
        "{s:i,s:i,s:i,s:K,s:s,s:s,s:i,s:i,s:i,s:K,s:K,s:K}",
        "attempted", count_i,
        "sent", static_cast<int>(sent_total),
        "errors", static_cast<int>(requested > sent_total ? (requested - sent_total) : 0),
        "bytes_sent_est", sent_total * static_cast<uint64_t>(packet_size),
        "sender_path", "DPDK_PMD",
        "sender_fallback_reason", "none",
        "fallback_count", 0,
        "dpdk_initialized", 1,
        "dpdk_link_up", 1,
        "dpdk_tx_packets", sent_total,
        "dpdk_tx_bytes", sent_total * static_cast<uint64_t>(packet_size),
        "dpdk_tx_dropped", dropped_total
    );
}

static PyObject* py_dpdk_poll_rx(PyObject*, PyObject* args) {
    long handle = 0;
    int budget_i = 0;
    if (!PyArg_ParseTuple(args, "li", &handle, &budget_i)) {
        return nullptr;
    }

    uint16_t port_id = 0;
    uint16_t queue_id = 0;
    bool rx_enable = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_contexts.find(handle);
        if (it == g_contexts.end()) {
            PyErr_SetString(PyExc_RuntimeError, "dpdk_invalid_handle");
            return nullptr;
        }
        port_id = it->second.port_id;
        queue_id = it->second.queue_id;
        rx_enable = it->second.rx_enable;
    }

    if (!rx_enable) {
        return PyList_New(0);
    }

    const uint16_t budget = static_cast<uint16_t>(std::clamp(budget_i, 0, static_cast<int>(kMaxBurst)));
    if (budget == 0) {
        return PyList_New(0);
    }

    rte_mbuf* mbufs[kMaxBurst];
    uint16_t n = 0;

    Py_BEGIN_ALLOW_THREADS
    n = rte_eth_rx_burst(port_id, queue_id, mbufs, budget);
    Py_END_ALLOW_THREADS

    PyObject* out = PyList_New(n);
    if (!out) {
        for (uint16_t i = 0; i < n; ++i) {
            rte_pktmbuf_free(mbufs[i]);
        }
        return nullptr;
    }

    uint64_t rx_bytes = 0;
    for (uint16_t i = 0; i < n; ++i) {
        const uint16_t pkt_len = rte_pktmbuf_pkt_len(mbufs[i]);
        const void* data = rte_pktmbuf_mtod(mbufs[i], const void*);
        PyObject* b = PyBytes_FromStringAndSize(static_cast<const char*>(data), pkt_len);
        rte_pktmbuf_free(mbufs[i]);
        if (!b) {
            Py_DECREF(out);
            return nullptr;
        }
        PyList_SET_ITEM(out, i, b);
        rx_bytes += pkt_len;
    }

    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_contexts.find(handle);
        if (it != g_contexts.end()) {
            it->second.rx_packets.fetch_add(n, std::memory_order_relaxed);
            it->second.rx_bytes.fetch_add(rx_bytes, std::memory_order_relaxed);
        }
    }
    return out;
}

static PyObject* py_dpdk_snapshot(PyObject*, PyObject* args) {
    long handle = 0;
    if (!PyArg_ParseTuple(args, "l", &handle)) {
        return nullptr;
    }

    uint16_t port_id = 0;
    uint16_t queue_id = 0;
    uint16_t burst_size = 64;
    int socket_id = 0;
    uint64_t tx_packets = 0;
    uint64_t tx_bytes = 0;
    uint64_t tx_errors = 0;
    uint64_t tx_dropped = 0;
    uint64_t rx_packets = 0;
    uint64_t rx_bytes = 0;
    uint64_t rx_dropped = 0;
    uint64_t mbuf_alloc_failures = 0;
    PortState port;
    bool has_port = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_contexts.find(handle);
        if (it == g_contexts.end()) {
            return PyDict_New();
        }
        port_id = it->second.port_id;
        queue_id = it->second.queue_id;
        burst_size = it->second.burst_size;
        socket_id = it->second.socket_id;
        tx_packets = it->second.tx_packets.load(std::memory_order_relaxed);
        tx_bytes = it->second.tx_bytes.load(std::memory_order_relaxed);
        tx_errors = it->second.tx_errors.load(std::memory_order_relaxed);
        tx_dropped = it->second.tx_dropped.load(std::memory_order_relaxed);
        rx_packets = it->second.rx_packets.load(std::memory_order_relaxed);
        rx_bytes = it->second.rx_bytes.load(std::memory_order_relaxed);
        rx_dropped = it->second.rx_dropped.load(std::memory_order_relaxed);
        mbuf_alloc_failures = it->second.mbuf_alloc_failures.load(std::memory_order_relaxed);
        auto pt = g_ports.find(port_id);
        if (pt != g_ports.end()) {
            port = pt->second;
            has_port = true;
        }
    }

    int link_up = 0;
    if (has_port && port.started) {
        rte_eth_link link;
        std::memset(&link, 0, sizeof(link));
        if (rte_eth_link_get_nowait(port_id, &link) == 0) {
            link_up = link.link_status ? 1 : 0;
        }
    }

    uint64_t mempool_avail = 0;
    if (has_port && port.mempool) {
        mempool_avail = rte_mempool_avail_count(port.mempool);
    }

    return Py_BuildValue(
        "{s:i,s:i,s:i,s:i,s:i,s:i,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:i,s:K,s:K}",
        "dpdk_available", 1,
        "dpdk_initialized", 1,
        "dpdk_port_id", static_cast<int>(port_id),
        "dpdk_queue_id", static_cast<int>(queue_id),
        "dpdk_socket_id", socket_id,
        "dpdk_link_up", link_up,
        "dpdk_tx_packets", tx_packets,
        "dpdk_tx_bytes", tx_bytes,
        "dpdk_tx_errors", tx_errors,
        "dpdk_tx_dropped", tx_dropped,
        "dpdk_rx_packets", rx_packets,
        "dpdk_rx_bytes", rx_bytes,
        "dpdk_rx_dropped", rx_dropped,
        "dpdk_burst_size", static_cast<int>(burst_size),
        "dpdk_mempool_avail", mempool_avail,
        "dpdk_mbuf_alloc_failures", mbuf_alloc_failures
    );
}

static PyObject* py_dpdk_close(PyObject*, PyObject* args) {
    long handle = 0;
    if (!PyArg_ParseTuple(args, "l", &handle)) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_contexts.find(handle);
    if (it != g_contexts.end()) {
        const uint16_t port_id = it->second.port_id;
        auto pt = g_ports.find(port_id);
        if (pt != g_ports.end()) {
            if (pt->second.users > 0) {
                pt->second.users -= 1;
            }
            if (pt->second.users == 0) {
                teardown_port_unlocked(port_id, pt->second);
                g_ports.erase(pt);
            }
        }
        g_contexts.erase(it);
    }
    Py_RETURN_NONE;
}

PyMethodDef module_methods[] = {
    {"dpdk_available", py_dpdk_available, METH_NOARGS, "Return DPDK availability"},
    {"dpdk_open", py_dpdk_open, METH_VARARGS, "Open DPDK context"},
    {"dpdk_send_batch", py_dpdk_send_batch, METH_VARARGS, "Send fixed-size batch"},
    {"dpdk_poll_rx", py_dpdk_poll_rx, METH_VARARGS, "Poll RX frames"},
    {"dpdk_snapshot", py_dpdk_snapshot, METH_VARARGS, "Snapshot DPDK counters"},
    {"dpdk_close", py_dpdk_close, METH_VARARGS, "Close DPDK context"},
    {nullptr, nullptr, 0, nullptr},
};

PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "dpdk_pmd_core",
    "DPDK PMD native backend",
    -1,
    module_methods,
};

} // namespace

PyMODINIT_FUNC PyInit_dpdk_pmd_core(void) {
    return PyModule_Create(&module_def);
}
