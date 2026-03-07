#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

typedef struct {
    long id;
    long attempted;
    long sent;
    long errors;
    long batches;
    long backend_success_batches;
    long backend_fallback_batches;
    int closed;
    int xdp_enable;
    int xdp_initialized;
    int queue_id;
    int xdp_mode;
    int raw_sockfd;
    int allow_python_fallback;
    char auto_resolve_reason[96];
    char backend[32];
    char fallback_policy[16];
    char interface[IFNAMSIZ];
    PyObject *xdp_mod;
    PyObject *fast_mod;
    PyObject *senders_mod;
} DpHandle;

static long g_next_id = 1;

static void _copy_lower(char *dst, size_t dst_len, const char *src, const char *fallback) {
    size_t i = 0;
    const char *s = (src != NULL && src[0] != '\0') ? src : fallback;

    if (dst == NULL || dst_len == 0) {
        return;
    }
    if (s == NULL) {
        s = "";
    }

    for (i = 0; i + 1 < dst_len && s[i] != '\0'; i++) {
        dst[i] = (char)tolower((unsigned char)s[i]);
    }
    dst[i] = '\0';
}

static int _set_long(PyObject *dict, const char *key, long value) {
    PyObject *v = PyLong_FromLong(value);
    int rc;
    if (v == NULL) {
        return -1;
    }
    rc = PyDict_SetItemString(dict, key, v);
    Py_DECREF(v);
    return rc;
}

static int _set_longlong(PyObject *dict, const char *key, long long value) {
    PyObject *v = PyLong_FromLongLong(value);
    int rc;
    if (v == NULL) {
        return -1;
    }
    rc = PyDict_SetItemString(dict, key, v);
    Py_DECREF(v);
    return rc;
}

static int _set_str(PyObject *dict, const char *key, const char *value) {
    PyObject *v = PyUnicode_FromString(value != NULL ? value : "");
    int rc;
    if (v == NULL) {
        return -1;
    }
    rc = PyDict_SetItemString(dict, key, v);
    Py_DECREF(v);
    return rc;
}

static int _merge_dict(PyObject *dst, PyObject *src) {
    PyObject *k;
    PyObject *v;
    Py_ssize_t pos = 0;

    if (!PyDict_Check(src)) {
        return 0;
    }

    while (PyDict_Next(src, &pos, &k, &v)) {
        if (PyDict_SetItem(dst, k, v) < 0) {
            return -1;
        }
    }
    return 0;
}

static long _dict_long(PyObject *cfg, const char *key, long fallback) {
    PyObject *v;
    if (!PyDict_Check(cfg)) {
        return fallback;
    }
    v = PyDict_GetItemString(cfg, key);
    if (v == NULL) {
        return fallback;
    }
    if (PyLong_Check(v)) {
        return PyLong_AsLong(v);
    }
    if (PyFloat_Check(v)) {
        return (long)PyFloat_AsDouble(v);
    }
    return fallback;
}

static int _dict_bool(PyObject *cfg, const char *key, int fallback) {
    PyObject *v;
    int truthy;

    if (!PyDict_Check(cfg)) {
        return fallback;
    }
    v = PyDict_GetItemString(cfg, key);
    if (v == NULL) {
        return fallback;
    }
    truthy = PyObject_IsTrue(v);
    if (truthy < 0) {
        PyErr_Clear();
        return fallback;
    }
    return truthy ? 1 : 0;
}

static const char *_dict_cstr(PyObject *cfg, const char *key, const char *fallback) {
    PyObject *v;
    const char *s;

    if (!PyDict_Check(cfg)) {
        return fallback;
    }
    v = PyDict_GetItemString(cfg, key);
    if (v == NULL || !PyUnicode_Check(v)) {
        return fallback;
    }
    s = PyUnicode_AsUTF8(v);
    if (s == NULL || s[0] == '\0') {
        PyErr_Clear();
        return fallback;
    }
    return s;
}

static long _py_dict_long(PyObject *dict, const char *key, long fallback) {
    PyObject *v;

    if (!PyDict_Check(dict)) {
        return fallback;
    }
    v = PyDict_GetItemString(dict, key);
    if (v == NULL) {
        return fallback;
    }
    if (PyLong_Check(v)) {
        return PyLong_AsLong(v);
    }
    if (PyFloat_Check(v)) {
        return (long)PyFloat_AsDouble(v);
    }
    return fallback;
}

static const char *_py_dict_cstr(PyObject *dict, const char *key, const char *fallback) {
    PyObject *v;
    const char *s;

    if (!PyDict_Check(dict)) {
        return fallback;
    }
    v = PyDict_GetItemString(dict, key);
    if (v == NULL || !PyUnicode_Check(v)) {
        return fallback;
    }
    s = PyUnicode_AsUTF8(v);
    if (s == NULL || s[0] == '\0') {
        PyErr_Clear();
        return fallback;
    }
    return s;
}

static void _capture_exception_type(char *out, size_t out_len, const char *prefix) {
    PyObject *ptype = NULL;
    PyObject *pvalue = NULL;
    PyObject *ptb = NULL;
    PyObject *name_obj = NULL;
    const char *name_utf8 = NULL;
    char type_name[64];

    if (out == NULL || out_len == 0) {
        PyErr_Clear();
        return;
    }

    (void)snprintf(type_name, sizeof(type_name), "Exception");

    PyErr_Fetch(&ptype, &pvalue, &ptb);
    PyErr_NormalizeException(&ptype, &pvalue, &ptb);

    if (ptype != NULL) {
        name_obj = PyObject_GetAttrString(ptype, "__name__");
        if (name_obj != NULL) {
            name_utf8 = PyUnicode_AsUTF8(name_obj);
            if (name_utf8 != NULL && name_utf8[0] != '\0') {
                (void)snprintf(type_name, sizeof(type_name), "%s", name_utf8);
            } else {
                PyErr_Clear();
            }
            Py_DECREF(name_obj);
        } else {
            PyErr_Clear();
        }
    }

    if (prefix != NULL && prefix[0] != '\0') {
        (void)snprintf(out, out_len, "%s:%s", prefix, type_name);
    } else {
        (void)snprintf(out, out_len, "%s", type_name);
    }

    Py_XDECREF(ptype);
    Py_XDECREF(pvalue);
    Py_XDECREF(ptb);
}

static PyObject *_import_cached(PyObject **slot, const char *module_name) {
    PyObject *mod;

    if (slot == NULL || module_name == NULL) {
        return NULL;
    }
    if (*slot != NULL) {
        Py_INCREF(*slot);
        return *slot;
    }

    mod = PyImport_ImportModule(module_name);
    if (mod == NULL) {
        return NULL;
    }
    *slot = mod;
    Py_INCREF(mod);
    return mod;
}

static void _resolve_auto_backend(DpHandle *h) {
    PyObject *xdp_mod = NULL;
    PyObject *fast_mod = NULL;
    int has_xdp_send = 0;
    int has_txring = 0;
    int has_cext = 0;

    if (h == NULL) {
        return;
    }
    if (strcmp(h->backend, "auto") != 0) {
        (void)snprintf(h->auto_resolve_reason, sizeof(h->auto_resolve_reason), "explicit_backend");
        return;
    }

    if (h->xdp_enable || h->interface[0] != '\0') {
        xdp_mod = _import_cached(&h->xdp_mod, "ddos_samurai.xdp_sender");
        if (xdp_mod != NULL) {
            has_xdp_send = PyObject_HasAttrString(xdp_mod, "xdp_send_buffer");
            Py_DECREF(xdp_mod);
            if (has_xdp_send) {
                (void)snprintf(h->backend, sizeof(h->backend), "%s", "xdp");
                (void)snprintf(h->auto_resolve_reason, sizeof(h->auto_resolve_reason), "auto->xdp");
                return;
            }
        } else {
            PyErr_Clear();
        }
    }

    fast_mod = _import_cached(&h->fast_mod, "ddos_samurai.fast_sender");
    if (fast_mod != NULL) {
        has_txring = PyObject_HasAttrString(fast_mod, "send_ring_optimized_ex");
        has_cext = PyObject_HasAttrString(fast_mod, "send_optimized");
        Py_DECREF(fast_mod);
        if (has_txring) {
            (void)snprintf(h->backend, sizeof(h->backend), "%s", "txring");
            (void)snprintf(h->auto_resolve_reason, sizeof(h->auto_resolve_reason), "auto->txring");
            return;
        }
        if (has_cext) {
            (void)snprintf(h->backend, sizeof(h->backend), "%s", "c_ext_l3");
            (void)snprintf(h->auto_resolve_reason, sizeof(h->auto_resolve_reason), "auto->c_ext_l3");
            return;
        }
    } else {
        PyErr_Clear();
    }

    if (h->allow_python_fallback) {
        (void)snprintf(h->backend, sizeof(h->backend), "%s", "python");
        (void)snprintf(h->auto_resolve_reason, sizeof(h->auto_resolve_reason), "auto->python");
        return;
    }

    (void)snprintf(h->backend, sizeof(h->backend), "%s", "unavailable");
    (void)snprintf(h->auto_resolve_reason, sizeof(h->auto_resolve_reason), "auto_no_backend");
}

static PyObject *_build_result(
    long attempted,
    long sent,
    long errors,
    int packet_size,
    const char *target_ip,
    int target_port,
    const char *sender_path,
    const char *reason,
    long fallback_count
) {
    PyObject *out = PyDict_New();
    long long bytes_sent_est = 0;

    if (out == NULL) {
        return NULL;
    }

    if (attempted < 0) {
        attempted = 0;
    }
    if (sent < 0) {
        sent = 0;
    }
    if (sent > attempted) {
        sent = attempted;
    }
    if (errors < 0) {
        errors = attempted - sent;
    }
    if (errors < 0) {
        errors = 0;
    }
    if (fallback_count < 0) {
        fallback_count = 0;
    }
    if (packet_size > 0 && sent > 0) {
        bytes_sent_est = (long long)packet_size * (long long)sent;
    }

    if (_set_long(out, "attempted", attempted) < 0 ||
        _set_long(out, "sent", sent) < 0 ||
        _set_long(out, "errors", errors) < 0 ||
        _set_longlong(out, "bytes_sent_est", bytes_sent_est) < 0 ||
        _set_str(out, "sender_path", sender_path != NULL ? sender_path : "DP_CORE") < 0 ||
        _set_str(out, "sender_fallback_reason", reason != NULL ? reason : "none") < 0 ||
        _set_long(out, "fallback_count", fallback_count) < 0 ||
        _set_str(out, "target_ip", target_ip != NULL ? target_ip : "") < 0 ||
        _set_long(out, "target_port", target_port) < 0 ||
        _set_long(out, "packet_size", packet_size) < 0) {
        Py_DECREF(out);
        return NULL;
    }

    return out;
}

static int _resolve_iface_only(DpHandle *h, const char *target_ip, char *iface_out, size_t iface_out_len) {
    PyObject *senders_mod = NULL;
    PyObject *gw = NULL;
    PyObject *iface_obj;
    const char *iface_utf8;

    if (iface_out == NULL || iface_out_len == 0) {
        return -1;
    }
    iface_out[0] = '\0';

    if (h != NULL && h->interface[0] != '\0') {
        (void)snprintf(iface_out, iface_out_len, "%s", h->interface);
        return 0;
    }

    senders_mod = _import_cached(&h->senders_mod, "ddos_samurai.senders");
    if (senders_mod == NULL) {
        PyErr_Clear();
        return -1;
    }

    gw = PyObject_CallMethod(senders_mod, "get_gateway_info", "s", target_ip != NULL ? target_ip : "");
    Py_DECREF(senders_mod);
    if (gw == NULL) {
        PyErr_Clear();
        return -1;
    }

    if (!PyTuple_Check(gw) || PyTuple_Size(gw) < 1) {
        Py_DECREF(gw);
        return -1;
    }

    iface_obj = PyTuple_GetItem(gw, 0);
    if (iface_obj == NULL || !PyUnicode_Check(iface_obj)) {
        Py_DECREF(gw);
        return -1;
    }

    iface_utf8 = PyUnicode_AsUTF8(iface_obj);
    if (iface_utf8 == NULL || iface_utf8[0] == '\0') {
        PyErr_Clear();
        Py_DECREF(gw);
        return -1;
    }

    (void)snprintf(iface_out, iface_out_len, "%s", iface_utf8);
    Py_DECREF(gw);
    return 0;
}

static int _resolve_txring_target(
    DpHandle *h,
    const char *target_ip,
    char *iface_out,
    size_t iface_out_len,
    PyObject **mac_out
) {
    PyObject *senders_mod = NULL;
    PyObject *gw = NULL;
    PyObject *iface_obj;
    PyObject *mac_obj;
    const char *iface_utf8;

    if (iface_out == NULL || iface_out_len == 0 || mac_out == NULL) {
        return -1;
    }

    iface_out[0] = '\0';
    *mac_out = NULL;

    senders_mod = _import_cached(&h->senders_mod, "ddos_samurai.senders");
    if (senders_mod == NULL) {
        PyErr_Clear();
        return -1;
    }

    gw = PyObject_CallMethod(senders_mod, "get_gateway_info", "s", target_ip != NULL ? target_ip : "");
    Py_DECREF(senders_mod);
    if (gw == NULL) {
        PyErr_Clear();
        return -1;
    }

    if (!PyTuple_Check(gw) || PyTuple_Size(gw) < 2) {
        Py_DECREF(gw);
        return -1;
    }

    iface_obj = PyTuple_GetItem(gw, 0);
    mac_obj = PyTuple_GetItem(gw, 1);

    if (iface_obj != NULL && PyUnicode_Check(iface_obj)) {
        iface_utf8 = PyUnicode_AsUTF8(iface_obj);
        if (iface_utf8 != NULL && iface_utf8[0] != '\0') {
            (void)snprintf(iface_out, iface_out_len, "%s", iface_utf8);
        } else {
            PyErr_Clear();
        }
    }

    if (iface_out[0] == '\0' && h != NULL && h->interface[0] != '\0') {
        (void)snprintf(iface_out, iface_out_len, "%s", h->interface);
    }

    if (iface_out[0] == '\0') {
        Py_DECREF(gw);
        return -1;
    }

    if (mac_obj == NULL || !PyBytes_Check(mac_obj) || PyBytes_GET_SIZE(mac_obj) != 6) {
        Py_DECREF(gw);
        return -1;
    }

    Py_INCREF(mac_obj);
    *mac_out = mac_obj;
    Py_DECREF(gw);
    return 0;
}

static PyObject *_run_txring_backend(
    DpHandle *h,
    PyObject *buffer_obj,
    int packet_size,
    int count,
    const char *target_ip,
    int target_port
) {
    PyObject *fast_mod = NULL;
    PyObject *mac_obj = NULL;
    PyObject *tx_result = NULL;
    PyObject *out = NULL;
    char iface[IFNAMSIZ];
    char reason[96];
    long attempted;
    long sent;
    long errors;

    reason[0] = '\0';
    iface[0] = '\0';

    fast_mod = _import_cached(&h->fast_mod, "ddos_samurai.fast_sender");
    if (fast_mod == NULL) {
        PyErr_Clear();
        return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_TX_RING_FAILED", "txring_module_unavailable", 1);
    }
    if (!PyObject_HasAttrString(fast_mod, "send_ring_optimized_ex")) {
        Py_DECREF(fast_mod);
        return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_TX_RING_FAILED", "txring_send_ex_missing", 1);
    }

    if (_resolve_txring_target(h, target_ip, iface, sizeof(iface), &mac_obj) < 0) {
        Py_DECREF(fast_mod);
        return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_TX_RING_FAILED", "txring_target_unresolved", 1);
    }

    tx_result = PyObject_CallMethod(
        fast_mod,
        "send_ring_optimized_ex",
        "sOiiO",
        iface,
        buffer_obj,
        packet_size,
        count,
        mac_obj
    );
    Py_DECREF(mac_obj);
    Py_DECREF(fast_mod);

    if (tx_result == NULL) {
        _capture_exception_type(reason, sizeof(reason), "txring_send_failed");
        return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_TX_RING_FAILED", reason, 1);
    }
    if (!PyDict_Check(tx_result)) {
        Py_DECREF(tx_result);
        return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_TX_RING_FAILED", "txring_invalid_result", 1);
    }

    attempted = _py_dict_long(tx_result, "attempted", count);
    sent = _py_dict_long(tx_result, "sent", 0);
    errors = _py_dict_long(tx_result, "errors", attempted - sent);

    if (attempted < 0) {
        attempted = 0;
    }
    if (sent < 0) {
        sent = 0;
    }
    if (sent > attempted) {
        sent = attempted;
    }
    if (errors < 0) {
        errors = attempted - sent;
    }
    if (errors < 0) {
        errors = 0;
    }

    out = _build_result(
        attempted,
        sent,
        errors,
        packet_size,
        target_ip,
        target_port,
        "DP_TX_RING",
        "none",
        0
    );
    if (out == NULL) {
        Py_DECREF(tx_result);
        return NULL;
    }

    if (_merge_dict(out, tx_result) < 0 ||
        _set_str(out, "sender_path", "DP_TX_RING") < 0 ||
        _set_str(out, "sender_fallback_reason", "none") < 0 ||
        _set_long(out, "fallback_count", 0) < 0) {
        Py_DECREF(tx_result);
        Py_DECREF(out);
        return NULL;
    }

    Py_DECREF(tx_result);
    return out;
}

static PyObject *_run_xdp_backend(
    DpHandle *h,
    PyObject *buffer_obj,
    int packet_size,
    int count,
    const char *target_ip,
    int target_port
) {
    PyObject *xdp_mod = NULL;
    PyObject *ret = NULL;
    PyObject *stats = NULL;
    PyObject *out = NULL;
    char iface[IFNAMSIZ];
    char reason[96];
    long sent = 0;
    long errors;

    reason[0] = '\0';
    iface[0] = '\0';

    xdp_mod = _import_cached(&h->xdp_mod, "ddos_samurai.xdp_sender");
    if (xdp_mod == NULL) {
        PyErr_Clear();
        return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_XDP_FAILED", "xdp_module_unavailable", 1);
    }
    if (!PyObject_HasAttrString(xdp_mod, "xdp_send_buffer")) {
        Py_DECREF(xdp_mod);
        return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_XDP_FAILED", "xdp_send_buffer_missing", 1);
    }

    if (_resolve_iface_only(h, target_ip, iface, sizeof(iface)) < 0 || iface[0] == '\0') {
        Py_DECREF(xdp_mod);
        return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_XDP_FAILED", "xdp_interface_missing", 1);
    }

    if (!h->xdp_initialized) {
        ret = PyObject_CallMethod(xdp_mod, "xdp_init", "sii", iface, h->queue_id, h->xdp_mode);
        if (ret == NULL) {
            _capture_exception_type(reason, sizeof(reason), "xdp_init_failed");
            Py_DECREF(xdp_mod);
            return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_XDP_FAILED", reason, 1);
        }
        if (!PyObject_IsTrue(ret)) {
            Py_DECREF(ret);
            Py_DECREF(xdp_mod);
            return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_XDP_FAILED", "xdp_init_rejected", 1);
        }
        Py_DECREF(ret);
        h->xdp_initialized = 1;
    }

    ret = PyObject_CallMethod(xdp_mod, "xdp_send_buffer", "Oii", buffer_obj, packet_size, count);
    if (ret == NULL) {
        h->xdp_initialized = 0;
        _capture_exception_type(reason, sizeof(reason), "xdp_send_failed");
        Py_DECREF(xdp_mod);
        return _build_result(count, 0, count, packet_size, target_ip, target_port, "DP_XDP_FAILED", reason, 1);
    }

    sent = PyLong_AsLong(ret);
    Py_DECREF(ret);
    if (PyErr_Occurred()) {
        PyErr_Clear();
        sent = 0;
    }

    if (sent < 0) {
        sent = 0;
    }
    if (sent > count) {
        sent = count;
    }
    errors = count - sent;
    if (errors < 0) {
        errors = 0;
    }

    out = _build_result(
        count,
        sent,
        errors,
        packet_size,
        target_ip,
        target_port,
        "DP_XDP",
        sent > 0 || count == 0 ? "none" : "xdp_sent_zero",
        sent > 0 || count == 0 ? 0 : 1
    );
    if (out == NULL) {
        Py_DECREF(xdp_mod);
        return NULL;
    }

    stats = PyObject_CallMethod(xdp_mod, "xdp_stats", NULL);
    Py_DECREF(xdp_mod);
    if (stats != NULL) {
        if (PyDict_Check(stats) && _merge_dict(out, stats) < 0) {
            Py_DECREF(stats);
            Py_DECREF(out);
            return NULL;
        }
        Py_DECREF(stats);
    } else {
        PyErr_Clear();
    }

    return out;
}

static int _ensure_raw_socket(DpHandle *h, char *reason_out, size_t reason_out_len) {
    int fd;

    if (h == NULL) {
        return -1;
    }
    if (h->raw_sockfd >= 0) {
        return 0;
    }

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        if (reason_out != NULL && reason_out_len > 0) {
            if (errno == EPERM || errno == EACCES) {
                (void)snprintf(reason_out, reason_out_len, "raw_socket_permission_denied");
            } else {
                (void)snprintf(reason_out, reason_out_len, "raw_socket_open_failed");
            }
        }
        return -1;
    }

    h->raw_sockfd = fd;
    return 0;
}

static PyObject *_run_c_ext_l3_backend(
    DpHandle *h,
    PyObject *buffer_obj,
    int packet_size,
    int count,
    const char *target_ip,
    int target_port
) {
    PyObject *fast_mod = NULL;
    PyObject *cext_result = NULL;
    PyObject *out = NULL;
    char reason[96];
    long attempted;
    long sent;
    long errors;
    long fallback_count = 0;
    const char *fallback_reason = "none";

    reason[0] = '\0';

    if (_ensure_raw_socket(h, reason, sizeof(reason)) < 0) {
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_C_EXT_L3_FAILED",
            reason[0] != '\0' ? reason : "raw_socket_unavailable",
            1
        );
    }

    fast_mod = _import_cached(&h->fast_mod, "ddos_samurai.fast_sender");
    if (fast_mod == NULL) {
        PyErr_Clear();
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_C_EXT_L3_FAILED",
            "cext_module_unavailable",
            1
        );
    }
    if (!PyObject_HasAttrString(fast_mod, "send_optimized")) {
        Py_DECREF(fast_mod);
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_C_EXT_L3_FAILED",
            "cext_send_optimized_missing",
            1
        );
    }

    cext_result = PyObject_CallMethod(
        fast_mod,
        "send_optimized",
        "iOsiii",
        h->raw_sockfd,
        buffer_obj,
        target_ip != NULL ? target_ip : "",
        target_port,
        packet_size,
        count
    );
    Py_DECREF(fast_mod);
    if (cext_result == NULL) {
        _capture_exception_type(reason, sizeof(reason), "cext_send_failed");
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_C_EXT_L3_FAILED",
            reason,
            1
        );
    }

    attempted = count;
    if (PyDict_Check(cext_result)) {
        attempted = _py_dict_long(cext_result, "attempted", count);
        sent = _py_dict_long(cext_result, "sent", 0);
    } else {
        sent = PyLong_AsLong(cext_result);
        if (PyErr_Occurred()) {
            PyErr_Clear();
            sent = 0;
        }
    }

    if (attempted < 0) {
        attempted = 0;
    }
    if (sent < 0) {
        sent = 0;
    }
    if (sent > attempted) {
        sent = attempted;
    }
    errors = attempted - sent;
    if (errors < 0) {
        errors = 0;
    }

    if (sent <= 0 && attempted > 0) {
        fallback_count = 1;
        fallback_reason = "cext_sent_zero";
    }

    out = _build_result(
        attempted,
        sent,
        errors,
        packet_size,
        target_ip,
        target_port,
        "DP_C_EXT_L3",
        fallback_reason,
        fallback_count
    );
    if (out == NULL) {
        Py_DECREF(cext_result);
        return NULL;
    }

    if (PyDict_Check(cext_result)) {
        const char *core_reason = _py_dict_cstr(cext_result, "sender_fallback_reason", "");
        long core_fb = _py_dict_long(cext_result, "fallback_count", fallback_count);
        if (_merge_dict(out, cext_result) < 0) {
            Py_DECREF(cext_result);
            Py_DECREF(out);
            return NULL;
        }
        if (_set_str(out, "sender_path", "DP_C_EXT_L3") < 0) {
            Py_DECREF(cext_result);
            Py_DECREF(out);
            return NULL;
        }
        if (core_reason != NULL && core_reason[0] != '\0' && strcmp(core_reason, "none") != 0) {
            if (_set_str(out, "sender_fallback_reason", core_reason) < 0) {
                Py_DECREF(cext_result);
                Py_DECREF(out);
                return NULL;
            }
            if (core_fb < 0) {
                core_fb = 0;
            }
            if (_set_long(out, "fallback_count", core_fb) < 0) {
                Py_DECREF(cext_result);
                Py_DECREF(out);
                return NULL;
            }
        } else if (fallback_count == 0) {
            if (_set_str(out, "sender_fallback_reason", "none") < 0 ||
                _set_long(out, "fallback_count", 0) < 0) {
                Py_DECREF(cext_result);
                Py_DECREF(out);
                return NULL;
            }
        }
    }

    Py_DECREF(cext_result);
    return out;
}

static PyObject *_run_python_backend(
    DpHandle *h,
    PyObject *buffer_obj,
    int packet_size,
    int count,
    const char *target_ip,
    int target_port
) {
    Py_buffer view;
    struct sockaddr_in addr;
    char reason[96];
    long sent = 0;
    long errors;
    PyObject *out;

    reason[0] = '\0';

    if (_ensure_raw_socket(h, reason, sizeof(reason)) < 0) {
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_PYTHON_SENDTO_FAILED",
            reason[0] != '\0' ? reason : "raw_socket_unavailable",
            1
        );
    }

    if (target_ip == NULL || target_ip[0] == '\0') {
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_PYTHON_SENDTO_FAILED",
            "target_ip_missing",
            1
        );
    }
    if (target_port <= 0 || target_port > 65535) {
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_PYTHON_SENDTO_FAILED",
            "target_port_invalid",
            1
        );
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)target_port);
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) != 1) {
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_PYTHON_SENDTO_FAILED",
            "target_ip_invalid",
            1
        );
    }

    if (packet_size <= 0) {
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_PYTHON_SENDTO_FAILED",
            "packet_size_invalid",
            1
        );
    }

    if (PyObject_GetBuffer(buffer_obj, &view, PyBUF_SIMPLE) < 0) {
        PyErr_Clear();
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_PYTHON_SENDTO_FAILED",
            "buffer_unavailable",
            1
        );
    }

    if ((size_t)view.len < ((size_t)packet_size * (size_t)count)) {
        PyBuffer_Release(&view);
        return _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_PYTHON_SENDTO_FAILED",
            "buffer_too_small",
            1
        );
    }

    for (int i = 0; i < count; i++) {
        const uint8_t *pkt = (const uint8_t *)view.buf + ((size_t)i * (size_t)packet_size);
        ssize_t n;
        for (;;) {
            n = sendto(
                h->raw_sockfd,
                pkt,
                (size_t)packet_size,
                MSG_NOSIGNAL,
                (const struct sockaddr *)&addr,
                sizeof(addr)
            );
            if (n >= 0) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == (ssize_t)packet_size) {
            sent += 1;
        }
    }

    PyBuffer_Release(&view);

    errors = count - sent;
    if (errors < 0) {
        errors = 0;
    }

    out = _build_result(
        count,
        sent,
        errors,
        packet_size,
        target_ip,
        target_port,
        "DP_PYTHON_SENDTO",
        (sent > 0 || count == 0) ? "none" : "python_sendto_failed",
        (sent > 0 || count == 0) ? 0 : 1
    );
    if (out == NULL) {
        return NULL;
    }
    if (_set_long(out, "py_sendto_fd", h->raw_sockfd) < 0) {
        Py_DECREF(out);
        return NULL;
    }

    return out;
}

static void _cleanup_handle(DpHandle *h) {
    PyObject *ret;

    if (h == NULL) {
        return;
    }

    if (h->xdp_initialized && h->xdp_mod != NULL && !h->closed) {
        ret = PyObject_CallMethod(h->xdp_mod, "xdp_cleanup", NULL);
        if (ret != NULL) {
            Py_DECREF(ret);
        } else {
            PyErr_Clear();
        }
        h->xdp_initialized = 0;
    }

    Py_XDECREF(h->xdp_mod);
    Py_XDECREF(h->fast_mod);
    Py_XDECREF(h->senders_mod);
    h->xdp_mod = NULL;
    h->fast_mod = NULL;
    h->senders_mod = NULL;
    if (h->raw_sockfd >= 0) {
        close(h->raw_sockfd);
        h->raw_sockfd = -1;
    }
}

static void _capsule_destructor(PyObject *capsule) {
    DpHandle *h = (DpHandle *)PyCapsule_GetPointer(capsule, "samurai.dataplane.handle");
    if (h == NULL) {
        PyErr_Clear();
        return;
    }
    _cleanup_handle(h);
    PyMem_Free(h);
}

static DpHandle *_get_handle(PyObject *obj) {
    return (DpHandle *)PyCapsule_GetPointer(obj, "samurai.dataplane.handle");
}

static PyObject *dp_open(PyObject *self, PyObject *args) {
    PyObject *cfg = NULL;
    DpHandle *h = NULL;
    const char *backend = "auto";
    const char *fallback_policy = "allow";
    const char *core_mode = "off";
    const char *iface = "";

    (void)self;

    if (!PyArg_ParseTuple(args, "O", &cfg)) {
        return NULL;
    }

    h = (DpHandle *)PyMem_Calloc(1, sizeof(DpHandle));
    if (h == NULL) {
        return PyErr_NoMemory();
    }

    h->id = g_next_id++;
    h->queue_id = 0;
    h->xdp_mode = 0;
    h->xdp_enable = 0;
    h->xdp_initialized = 0;
    h->raw_sockfd = -1;
    h->allow_python_fallback = 0;
    h->auto_resolve_reason[0] = '\0';

    _copy_lower(h->backend, sizeof(h->backend), "auto", "auto");
    _copy_lower(h->fallback_policy, sizeof(h->fallback_policy), "allow", "allow");
    h->interface[0] = '\0';

    if (PyDict_Check(cfg)) {
        backend = _dict_cstr(cfg, "backend", "auto");
        fallback_policy = _dict_cstr(cfg, "fallback_policy", "allow");
        core_mode = _dict_cstr(cfg, "core_mode", "off");
        iface = _dict_cstr(cfg, "interface", "");
        h->queue_id = (int)_dict_long(cfg, "queue_id", 0);
        h->xdp_enable = _dict_bool(cfg, "xdp_enable", 0);
        h->xdp_mode = (int)_dict_long(cfg, "xdp_mode", 0);
        h->allow_python_fallback = _dict_bool(cfg, "allow_python_fallback", 0);
    }

    _copy_lower(h->backend, sizeof(h->backend), backend, "auto");
    _copy_lower(h->fallback_policy, sizeof(h->fallback_policy), fallback_policy, "allow");
    if (strcmp(h->fallback_policy, "deny") == 0) {
        (void)snprintf(h->fallback_policy, sizeof(h->fallback_policy), "fail");
    } else if (strcmp(h->fallback_policy, "allow") != 0 && strcmp(h->fallback_policy, "fail") != 0) {
        (void)snprintf(h->fallback_policy, sizeof(h->fallback_policy), "allow");
    }
    if (strcmp(core_mode, "required") == 0) {
        h->allow_python_fallback = 0;
    }
    (void)snprintf(h->interface, sizeof(h->interface), "%s", iface != NULL ? iface : "");
    _resolve_auto_backend(h);

    return PyCapsule_New((void *)h, "samurai.dataplane.handle", _capsule_destructor);
}

static PyObject *dp_send_batch(PyObject *self, PyObject *args) {
    PyObject *handle_obj = NULL;
    PyObject *buffer_obj = NULL;
    int packet_size = 0;
    int count = 0;
    const char *target_ip = "";
    int target_port = 0;
    DpHandle *h = NULL;
    PyObject *out = NULL;
    const char *backend = NULL;
    long attempted;
    long sent;
    long errors;
    long fallback_count;

    (void)self;

    if (!PyArg_ParseTuple(args, "OOiisi", &handle_obj, &buffer_obj, &packet_size, &count, &target_ip, &target_port)) {
        return NULL;
    }

    h = _get_handle(handle_obj);
    if (h == NULL) {
        return NULL;
    }

    if (h->closed) {
        PyErr_SetString(PyExc_RuntimeError, "dataplane handle is closed");
        return NULL;
    }

    if (count < 0) {
        count = 0;
    }
    if (packet_size < 0) {
        packet_size = 0;
    }

    backend = h->backend[0] != '\0' ? h->backend : "auto";
    if (strcmp(backend, "auto") == 0) {
        _resolve_auto_backend(h);
        backend = h->backend[0] != '\0' ? h->backend : "unavailable";
    }

    if (count == 0) {
        out = _build_result(0, 0, 0, packet_size, target_ip, target_port, "DP_NONE", "none", 0);
    } else if (strcmp(backend, "xdp") == 0) {
        out = _run_xdp_backend(h, buffer_obj, packet_size, count, target_ip, target_port);
    } else if (strcmp(backend, "txring") == 0) {
        out = _run_txring_backend(h, buffer_obj, packet_size, count, target_ip, target_port);
    } else if (strcmp(backend, "c_ext_l3") == 0) {
        out = _run_c_ext_l3_backend(h, buffer_obj, packet_size, count, target_ip, target_port);
    } else if (strcmp(backend, "python") == 0) {
        out = _run_python_backend(h, buffer_obj, packet_size, count, target_ip, target_port);
    } else if (strcmp(backend, "unavailable") == 0) {
        const char *reason = h->auto_resolve_reason[0] != '\0' ? h->auto_resolve_reason : "auto_no_backend";
        out = _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_BACKEND_UNAVAILABLE",
            reason,
            1
        );
    } else {
        out = _build_result(
            count,
            0,
            count,
            packet_size,
            target_ip,
            target_port,
            "DP_UNHANDLED_BACKEND",
            "backend_unhandled",
            1
        );
    }

    if (out == NULL) {
        return NULL;
    }

    if (_set_long(out, "dp_queue_id", h->queue_id) < 0 ||
        _set_str(out, "dp_backend", backend) < 0 ||
        _set_long(out, "xdp_enabled", h->xdp_enable ? 1 : 0) < 0 ||
        _set_str(out, "dp_interface", h->interface) < 0) {
        Py_DECREF(out);
        return NULL;
    }

    attempted = _py_dict_long(out, "attempted", count);
    sent = _py_dict_long(out, "sent", 0);
    errors = _py_dict_long(out, "errors", attempted - sent);
    fallback_count = _py_dict_long(out, "fallback_count", 0);

    if (attempted < 0) {
        attempted = 0;
    }
    if (sent < 0) {
        sent = 0;
    }
    if (sent > attempted) {
        sent = attempted;
    }
    if (errors < 0) {
        errors = attempted - sent;
    }
    if (errors < 0) {
        errors = 0;
    }
    if (fallback_count < 0) {
        fallback_count = 0;
    }

    h->attempted += attempted;
    h->sent += sent;
    h->errors += errors;
    h->batches += 1;
    if (sent > 0) {
        h->backend_success_batches += 1;
    }
    if (fallback_count > 0) {
        h->backend_fallback_batches += 1;
    }

    return out;
}

static PyObject *dp_snapshot(PyObject *self, PyObject *args) {
    PyObject *handle_obj = NULL;
    DpHandle *h = NULL;
    PyObject *out = NULL;

    (void)self;

    if (!PyArg_ParseTuple(args, "O", &handle_obj)) {
        return NULL;
    }

    h = _get_handle(handle_obj);
    if (h == NULL) {
        return NULL;
    }

    out = PyDict_New();
    if (out == NULL) {
        return NULL;
    }

    if (_set_long(out, "id", h->id) < 0 ||
        _set_long(out, "attempted", h->attempted) < 0 ||
        _set_long(out, "sent", h->sent) < 0 ||
        _set_long(out, "errors", h->errors) < 0 ||
        _set_long(out, "batches", h->batches) < 0 ||
        _set_long(out, "backend_success_batches", h->backend_success_batches) < 0 ||
        _set_long(out, "backend_fallback_batches", h->backend_fallback_batches) < 0 ||
        _set_str(out, "backend", h->backend) < 0 ||
        _set_str(out, "fallback_policy", h->fallback_policy) < 0 ||
        _set_str(out, "interface", h->interface) < 0 ||
        _set_long(out, "queue_id", h->queue_id) < 0 ||
        _set_long(out, "xdp_enable", h->xdp_enable ? 1 : 0) < 0 ||
        _set_long(out, "xdp_initialized", h->xdp_initialized ? 1 : 0) < 0 ||
        _set_long(out, "closed", h->closed ? 1 : 0) < 0) {
        Py_DECREF(out);
        return NULL;
    }

    return out;
}

static PyObject *dp_close(PyObject *self, PyObject *args) {
    PyObject *handle_obj = NULL;
    DpHandle *h = NULL;

    (void)self;

    if (!PyArg_ParseTuple(args, "O", &handle_obj)) {
        return NULL;
    }

    h = _get_handle(handle_obj);
    if (h == NULL) {
        return NULL;
    }

    _cleanup_handle(h);
    h->closed = 1;
    Py_RETURN_NONE;
}

static PyMethodDef DataplaneMethods[] = {
    {"open", dp_open, METH_VARARGS, "open(config) -> handle"},
    {"send_batch", dp_send_batch, METH_VARARGS, "send_batch(handle, buffer, packet_size, count, target_ip, target_port)"},
    {"snapshot", dp_snapshot, METH_VARARGS, "snapshot(handle) -> counters"},
    {"close", dp_close, METH_VARARGS, "close(handle)"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef dataplane_module = {
    PyModuleDef_HEAD_INIT,
    "dataplane_core",
    "Samurai dataplane core (TX_RING/XDP dispatcher)",
    -1,
    DataplaneMethods
};

PyMODINIT_FUNC PyInit_dataplane_core(void) {
    return PyModule_Create(&dataplane_module);
}
