#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "l4_state_engine_ffi.h"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <vector>

extern "C" void l4se_shutdown_all_handlers(void);

namespace {

uint32_t EnvUInt(const char* name, uint32_t fallback) {
  const char* raw = getenv(name);
  char* endptr = nullptr;
  unsigned long parsed = 0;
  if (!raw || !raw[0]) {
    return fallback;
  }
  errno = 0;
  parsed = strtoul(raw, &endptr, 10);
  if (errno != 0 || endptr == raw || (endptr && *endptr != '\0')) {
    return fallback;
  }
  if (parsed == 0UL || parsed > 0x7fffffffUL) {
    return fallback;
  }
  return static_cast<uint32_t>(parsed);
}

PyObject* configure_state_engine(PyObject* self, PyObject* args) {
  (void)self;
  unsigned int table_size = 65536;
  unsigned int lock_count = 256;
  unsigned int timeout_sec = 60;
  if (!PyArg_ParseTuple(args, "III", &table_size, &lock_count, &timeout_sec)) {
    return nullptr;
  }
  if (table_size == 0 || lock_count == 0 || timeout_sec == 0 || (table_size % lock_count) != 0) {
    PyErr_SetString(
        PyExc_ValueError,
        "Invalid state-engine config: table_size/lock_count/timeout_sec must be >0 and table_size % lock_count == 0");
    return nullptr;
  }
  if (l4se_configure(static_cast<uint32_t>(table_size), static_cast<uint32_t>(lock_count), static_cast<uint32_t>(timeout_sec)) !=
      0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to initialize L4 state engine");
    return nullptr;
  }
  return Py_BuildValue(
      "{s:I,s:I,s:I}",
      "table_size",
      table_size,
      "lock_count",
      lock_count,
      "timeout_sec",
      timeout_sec);
}

PyObject* set_mimicry_settings(PyObject* self, PyObject* args) {
  (void)self;
  uint16_t window = 0;
  uint16_t mss = 0;
  unsigned int ttl_raw = 0;
  if (!PyArg_ParseTuple(args, "HHI", &window, &mss, &ttl_raw)) {
    return nullptr;
  }
  if (ttl_raw > 255U) {
    PyErr_SetString(PyExc_ValueError, "ttl must be in range [0,255]");
    return nullptr;
  }
  const uint8_t ttl = static_cast<uint8_t>(ttl_raw);
  if (l4se_set_mimicry(window, mss, ttl) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to apply mimicry settings");
    return nullptr;
  }
  Py_RETURN_NONE;
}

PyObject* get_state_engine_stats(PyObject* self, PyObject* args) {
  (void)self;
  (void)args;
  l4se_stats_snapshot_t st {};
  if (l4se_stats_snapshot(&st) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to snapshot state engine stats");
    return nullptr;
  }

  PyObject* state_counts = PyList_New(7);
  if (!state_counts) {
    return nullptr;
  }
  for (Py_ssize_t i = 0; i < 7; ++i) {
    PyObject* item = PyLong_FromUnsignedLongLong(st.state_counts[i]);
    if (!item) {
      Py_DECREF(state_counts);
      return nullptr;
    }
    PyList_SET_ITEM(state_counts, i, item);
  }

  PyObject* out = Py_BuildValue(
      "{s:I,s:I,s:I,s:K,s:K,s:K,s:K,s:K,s:I,s:K,s:O}",
      "table_size",
      st.table_size,
      "lock_count",
      st.lock_count,
      "timeout_sec",
      st.timeout_sec,
      "active_entries",
      st.active_entries,
      "timeout_evictions",
      st.timeout_evictions,
      "overwrites",
      st.overwrites,
      "sweeps",
      st.sweeps,
      "last_sweep_removed",
      st.last_sweep_removed,
      "sweep_cursor",
      st.sweep_cursor,
      "transition_total",
      st.transition_total,
      "state_counts",
      state_counts);
  Py_DECREF(state_counts);
  return out;
}

PyObject* ingest_tx_packets(PyObject* self, PyObject* args) {
  (void)self;
  Py_buffer view;
  int packet_size = 0;
  int count = 0;
  if (!PyArg_ParseTuple(args, "y*ii", &view, &packet_size, &count)) {
    return nullptr;
  }
  if (packet_size <= 0 || count <= 0) {
    PyBuffer_Release(&view);
    return PyLong_FromLong(0);
  }
  const size_t required = static_cast<size_t>(packet_size) * static_cast<size_t>(count);
  if (static_cast<size_t>(view.len) < required) {
    PyBuffer_Release(&view);
    PyErr_SetString(PyExc_ValueError, "packets buffer is smaller than packet_size * count");
    return nullptr;
  }

  uint32_t updated = 0;
  const int rc = l4se_ingest_tx_packets(
      static_cast<const uint8_t*>(view.buf), static_cast<size_t>(packet_size), static_cast<size_t>(count), &updated);
  PyBuffer_Release(&view);
  if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to ingest TX packets in L4 state engine");
    return nullptr;
  }
  return PyLong_FromUnsignedLong(updated);
}

PyObject* ingest_rx_frame(PyObject* self, PyObject* args) {
  (void)self;
  Py_buffer view;
  if (!PyArg_ParseTuple(args, "y*", &view)) {
    return nullptr;
  }
  if (view.len <= 0) {
    PyBuffer_Release(&view);
    return PyLong_FromLong(0);
  }
  uint32_t updated = 0;
  const int rc = l4se_ingest_rx_frame(static_cast<const uint8_t*>(view.buf), static_cast<size_t>(view.len), &updated);
  PyBuffer_Release(&view);
  if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to ingest RX frame in L4 state engine");
    return nullptr;
  }
  return PyLong_FromUnsignedLong(updated);
}

PyObject* get_states_batch(PyObject* self, PyObject* args) {
  (void)self;
  uint32_t src_ip = 0;
  uint16_t start_port = 0;
  uint32_t count = 0;
  if (!PyArg_ParseTuple(args, "IHI", &src_ip, &start_port, &count)) {
    return nullptr;
  }

  std::vector<uint32_t> seq(count, 0);
  std::vector<uint32_t> ack(count, 0);
  std::vector<uint8_t> state(count, 0);
  std::vector<uint16_t> win(count, 0);
  std::vector<uint16_t> mss(count, 0);
  std::vector<uint8_t> ttl(count, 0);

  uint32_t found = 0;
  if (l4se_get_states_batch(
          src_ip,
          start_port,
          count,
          seq.data(),
          ack.data(),
          state.data(),
          win.data(),
          mss.data(),
          ttl.data(),
          &found) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to read states batch from L4 state engine");
    return nullptr;
  }

  PyObject* seq_list = PyList_New(static_cast<Py_ssize_t>(count));
  PyObject* ack_list = PyList_New(static_cast<Py_ssize_t>(count));
  PyObject* state_list = PyList_New(static_cast<Py_ssize_t>(count));
  PyObject* win_list = PyList_New(static_cast<Py_ssize_t>(count));
  PyObject* mss_list = PyList_New(static_cast<Py_ssize_t>(count));
  PyObject* ttl_list = PyList_New(static_cast<Py_ssize_t>(count));
  if (!seq_list || !ack_list || !state_list || !win_list || !mss_list || !ttl_list) {
    Py_XDECREF(seq_list);
    Py_XDECREF(ack_list);
    Py_XDECREF(state_list);
    Py_XDECREF(win_list);
    Py_XDECREF(mss_list);
    Py_XDECREF(ttl_list);
    return nullptr;
  }

  for (Py_ssize_t i = 0; i < static_cast<Py_ssize_t>(count); ++i) {
    PyList_SET_ITEM(seq_list, i, PyLong_FromUnsignedLong(seq[static_cast<size_t>(i)]));
    PyList_SET_ITEM(ack_list, i, PyLong_FromUnsignedLong(ack[static_cast<size_t>(i)]));
    PyList_SET_ITEM(state_list, i, PyLong_FromUnsignedLong(state[static_cast<size_t>(i)]));
    PyList_SET_ITEM(win_list, i, PyLong_FromUnsignedLong(win[static_cast<size_t>(i)]));
    PyList_SET_ITEM(mss_list, i, PyLong_FromUnsignedLong(mss[static_cast<size_t>(i)]));
    PyList_SET_ITEM(ttl_list, i, PyLong_FromUnsignedLong(ttl[static_cast<size_t>(i)]));
  }

  (void)found;
  return Py_BuildValue("NNNNNN", seq_list, ack_list, state_list, win_list, mss_list, ttl_list);
}

PyObject* get_tcp_state(PyObject* self, PyObject* args) {
  (void)self;
  uint32_t src_ip = 0;
  uint16_t src_port = 0;
  if (!PyArg_ParseTuple(args, "IH", &src_ip, &src_port)) {
    return nullptr;
  }

  uint32_t seq = 0;
  uint32_t ack = 0;
  uint8_t state = 0;
  uint16_t window = 0;
  uint16_t mss = 0;
  uint8_t ttl = 0;
  uint8_t found = 0;

  if (l4se_get_tcp_state(src_ip, src_port, &seq, &ack, &state, &window, &mss, &ttl, &found) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to read TCP state from L4 state engine");
    return nullptr;
  }

  return Py_BuildValue(
      "{s:I,s:I,s:i,s:H,s:H,s:b,s:i}",
      "seq",
      seq,
      "ack",
      ack,
      "state",
      static_cast<int>(state),
      "window",
      window,
      "mss",
      mss,
      "ttl",
      static_cast<signed char>(ttl),
      "found",
      static_cast<int>(found));
}

PyObject* sweep_state_table(PyObject* self, PyObject* args) {
  (void)self;
  unsigned int max_scan = 0;
  if (!PyArg_ParseTuple(args, "|I", &max_scan)) {
    return nullptr;
  }
  uint32_t removed = 0;
  if (l4se_sweep(static_cast<uint32_t>(max_scan), &removed) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to sweep L4 state engine");
    return nullptr;
  }
  return PyLong_FromUnsignedLong(removed);
}

PyObject* start_rx_handler(PyObject* self, PyObject* args) {
  (void)self;
  const char* iface = nullptr;
  if (!PyArg_ParseTuple(args, "s", &iface)) {
    return nullptr;
  }
  int32_t handler_id = -1;
  if (l4se_start_rx_handler(iface, &handler_id) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to start L4 RX handler");
    return nullptr;
  }
  return PyLong_FromLong(static_cast<long>(handler_id));
}

PyObject* stop_rx_handler(PyObject* self, PyObject* args) {
  (void)self;
  int handler_id = -1;
  if (!PyArg_ParseTuple(args, "i", &handler_id)) {
    return nullptr;
  }
  if (l4se_stop_rx_handler(static_cast<int32_t>(handler_id)) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to stop L4 RX handler");
    return nullptr;
  }
  Py_RETURN_NONE;
}

PyMethodDef kMethods[] = {
    {"configure_state_engine", configure_state_engine, METH_VARARGS, "Configure state table size/locks/timeout."},
    {"get_state_engine_stats", get_state_engine_stats, METH_NOARGS, "Return state-engine counters and active entries."},
    {"ingest_tx_packets", ingest_tx_packets, METH_VARARGS, "Ingest transmitted packets and update state table."},
    {"ingest_rx_frame", ingest_rx_frame, METH_VARARGS, "Ingest an RX frame and update state table."},
    {"sweep_state_table", sweep_state_table, METH_VARARGS, "Sweep stale state entries by timeout and return removed count."},
    {"get_tcp_state", get_tcp_state, METH_VARARGS, "Get TCP state from the state table."},
    {"get_states_batch", get_states_batch, METH_VARARGS, "Get multiple TCP states in one call."},
    {"start_rx_handler", start_rx_handler, METH_VARARGS, "Start background RX handler thread and return handler id."},
    {"stop_rx_handler", stop_rx_handler, METH_VARARGS, "Stop background RX handler by handler id."},
    {"set_mimicry_settings", set_mimicry_settings, METH_VARARGS, "Set global TCP mimicry settings (Window, MSS, TTL)."},
    {nullptr, nullptr, 0, nullptr},
};

void l4_state_engine_free(void* module) {
  (void)module;
  l4se_shutdown_all_handlers();
}

PyModuleDef kModuleDef = {
    PyModuleDef_HEAD_INIT,
    "state_engine",
    "L4 TCP state engine (C++20 core + C ABI)",
    -1,
    kMethods,
    nullptr,
    nullptr,
    nullptr,
    l4_state_engine_free,
};

}  // namespace

PyMODINIT_FUNC PyInit_state_engine(void) {
  const uint32_t cfg_table = EnvUInt("SAMURAI_STATE_TABLE_SIZE", 65536);
  const uint32_t cfg_locks = EnvUInt("SAMURAI_STATE_LOCK_COUNT", 256);
  const uint32_t cfg_timeout = EnvUInt("SAMURAI_STATE_TIMEOUT_SEC", 60);

  if (cfg_table == 0 || cfg_locks == 0 || cfg_timeout == 0 || (cfg_table % cfg_locks) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Invalid state-engine env config");
    return nullptr;
  }
  if (l4se_configure(cfg_table, cfg_locks, cfg_timeout) != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Failed to initialize L4 state engine");
    return nullptr;
  }
  return PyModule_Create(&kModuleDef);
}
