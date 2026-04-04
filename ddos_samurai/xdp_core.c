#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xdp_core.h"
#include "xdp_native_api.h"

struct xdp_core_handle {
    PyObject *xdp_mod;
    const xdp_native_api_v1 *native_api;
    PyObject *fn_init;
    PyObject *fn_send_buffer;
    PyObject *fn_send;
    PyObject *fn_stats;
    PyObject *fn_cleanup;
    PyObject *fn_create;
    PyObject *fn_destroy;
    int initialized;
    int use_ctx_api;
    int use_native_api;
    int ctx_handle;
    int mode_requested;
    int mode_effective;
    char mode2_policy[8];
    char mode2_probe_status[16];
    char mode2_probe_reason[96];
};

static void _err_set(xdp_core_err *err, int code, const char *msg) {
    if (!err) return;
    err->code = code;
    (void)snprintf(err->message, sizeof(err->message), "%s", msg ? msg : "xdp_core_error");
}

static void _copy_lower(char *dst, size_t dst_sz, const char *src, const char *fallback) {
    size_t i = 0;
    const char *s = (src && src[0]) ? src : fallback;
    if (!dst || dst_sz == 0) return;
    if (!s) s = "";
    for (; i + 1 < dst_sz && s[i]; i++) {
        dst[i] = (char)tolower((unsigned char)s[i]);
    }
    dst[i] = '\0';
}

static int _as_long(PyObject *obj, const char *key, long *out) {
    PyObject *v;
    if (!obj || !PyDict_Check(obj) || !key || !out) return -1;
    v = PyDict_GetItemString(obj, key); /* borrowed */
    if (!v) {
        *out = 0;
        return 0;
    }
    *out = PyLong_AsLong(v);
    if (PyErr_Occurred()) {
        PyErr_Clear();
        *out = 0;
    }
    return 0;
}

static void _release_handle_refs(xdp_core_handle *h) {
    if (!h) return;
    Py_XDECREF(h->fn_init); h->fn_init = NULL;
    Py_XDECREF(h->fn_send_buffer); h->fn_send_buffer = NULL;
    Py_XDECREF(h->fn_send); h->fn_send = NULL;
    Py_XDECREF(h->fn_stats); h->fn_stats = NULL;
    Py_XDECREF(h->fn_cleanup); h->fn_cleanup = NULL;
    Py_XDECREF(h->fn_create); h->fn_create = NULL;
    Py_XDECREF(h->fn_destroy); h->fn_destroy = NULL;
    Py_XDECREF(h->xdp_mod); h->xdp_mod = NULL;
    h->native_api = NULL;
    h->use_ctx_api = 0;
    h->use_native_api = 0;
    h->ctx_handle = 0;
}

int xdp_core_probe_mode2(const char *iface, xdp_probe_result *out, xdp_core_err *err) {
    PyObject *af_mod = NULL;
    PyObject *probe_fn = NULL;
    PyObject *ret = NULL;
    PyObject *st = NULL;
    PyObject *rs = NULL;
    const char *status = "unknown";
    const char *reason = "probe_unavailable";

    if (out) {
        (void)snprintf(out->status, sizeof(out->status), "%s", "unknown");
        (void)snprintf(out->reason, sizeof(out->reason), "%s", "probe_unavailable");
    }

    af_mod = PyImport_ImportModule("ddos_samurai.af_xdp_sender");
    if (!af_mod) {
        PyErr_Clear();
        af_mod = PyImport_ImportModule("af_xdp_sender");
    }
    if (!af_mod) {
        _err_set(err, 1, "af_xdp_sender module not importable");
        return -1;
    }

    probe_fn = PyObject_GetAttrString(af_mod, "probe_xdp_mode2_capability");
    if (!probe_fn || !PyCallable_Check(probe_fn)) {
        Py_XDECREF(probe_fn);
        Py_DECREF(af_mod);
        _err_set(err, 2, "probe_xdp_mode2_capability unavailable");
        return -1;
    }

    ret = PyObject_CallFunction(probe_fn, "s", iface ? iface : "");
    Py_DECREF(probe_fn);
    Py_DECREF(af_mod);
    if (!ret) {
        PyErr_Clear();
        _err_set(err, 3, "probe_xdp_mode2_capability call failed");
        return -1;
    }
    if (!PyTuple_Check(ret) || PyTuple_GET_SIZE(ret) < 2) {
        Py_DECREF(ret);
        _err_set(err, 4, "probe result must be tuple(status, reason)");
        return -1;
    }

    st = PyTuple_GET_ITEM(ret, 0); /* borrowed */
    rs = PyTuple_GET_ITEM(ret, 1); /* borrowed */
    status = PyUnicode_Check(st) ? PyUnicode_AsUTF8(st) : "unknown";
    reason = PyUnicode_Check(rs) ? PyUnicode_AsUTF8(rs) : "probe_unavailable";
    if (!status) status = "unknown";
    if (!reason) reason = "probe_unavailable";

    if (out) {
        (void)snprintf(out->status, sizeof(out->status), "%s", status);
        (void)snprintf(out->reason, sizeof(out->reason), "%s", reason);
    }
    Py_DECREF(ret);
    _err_set(err, 0, "");
    return 0;
}

xdp_core_handle *xdp_core_open(const xdp_core_open_cfg *cfg, xdp_core_err *err) {
    xdp_core_handle *h = NULL;
    PyObject *ret = NULL;
    xdp_probe_result probe;
    int hard_policy = 0;

    if (!cfg || !cfg->interface || !cfg->interface[0]) {
        _err_set(err, 10, "interface is required");
        return NULL;
    }

    h = (xdp_core_handle *)calloc(1, sizeof(*h));
    if (!h) {
        _err_set(err, 11, "out of memory");
        return NULL;
    }

    _copy_lower(h->mode2_policy, sizeof(h->mode2_policy), cfg->mode2_policy, "soft");
    if (strcmp(h->mode2_policy, "hard") != 0 && strcmp(h->mode2_policy, "soft") != 0) {
        (void)snprintf(h->mode2_policy, sizeof(h->mode2_policy), "%s", "soft");
    }
    hard_policy = (strcmp(h->mode2_policy, "hard") == 0) ? 1 : 0;

    h->mode_requested = cfg->mode;
    h->mode_effective = cfg->mode;
    (void)snprintf(h->mode2_probe_status, sizeof(h->mode2_probe_status), "%s", "not_run");
    (void)snprintf(h->mode2_probe_reason, sizeof(h->mode2_probe_reason), "%s", "not_run");

    h->xdp_mod = PyImport_ImportModule("ddos_samurai.xdp_sender");
    if (!h->xdp_mod) {
        PyErr_Clear();
        h->xdp_mod = PyImport_ImportModule("xdp_sender");
    }
    if (!h->xdp_mod) {
        free(h);
        _err_set(err, 12, "xdp_sender module not importable");
        return NULL;
    }

    {
        PyObject *cap = PyObject_GetAttrString(h->xdp_mod, "xdp_get_native_api");
        if (cap && PyCallable_Check(cap)) {
            PyObject *cap_obj = PyObject_CallNoArgs(cap);
            if (cap_obj) {
                void *ptr = PyCapsule_GetPointer(cap_obj, XDP_NATIVE_API_CAPSULE_NAME);
                if (ptr) {
                    const xdp_native_api_v1 *api = (const xdp_native_api_v1*)ptr;
                    if (api->version == XDP_NATIVE_API_VERSION &&
                        api->create_ctx && api->destroy_ctx &&
                        api->send_buffer && api->send_vector && api->get_stats) {
                        h->native_api = api;
                        h->use_native_api = 1;
                    }
                } else {
                    PyErr_Clear();
                }
                Py_DECREF(cap_obj);
            } else {
                PyErr_Clear();
            }
        }
        Py_XDECREF(cap);
    }

    if (h->use_native_api) {
        char nerr[160];
        if (h->mode_requested == 2) {
            if (xdp_core_probe_mode2(cfg->interface, &probe, NULL) == 0) {
                (void)snprintf(h->mode2_probe_status, sizeof(h->mode2_probe_status), "%s", probe.status);
                (void)snprintf(h->mode2_probe_reason, sizeof(h->mode2_probe_reason), "%s", probe.reason);
            } else {
                (void)snprintf(h->mode2_probe_status, sizeof(h->mode2_probe_status), "%s", "unknown");
                (void)snprintf(h->mode2_probe_reason, sizeof(h->mode2_probe_reason), "%s", "probe_unavailable");
            }
            if (hard_policy && strcmp(h->mode2_probe_status, "supported") != 0) {
                char msg[160];
                (void)snprintf(msg, sizeof(msg), "xdp_mode2_hard_probe_not_supported: %s", h->mode2_probe_reason);
                _release_handle_refs(h);
                free(h);
                _err_set(err, 14, msg);
                return NULL;
            }
            if (!hard_policy &&
                (strcmp(h->mode2_probe_status, "unsupported") == 0 ||
                 strcmp(h->mode2_probe_status, "unknown") == 0)) {
                h->mode_effective = 1;
            }
        }

        nerr[0] = '\0';
        h->ctx_handle = h->native_api->create_ctx(
            cfg->interface,
            cfg->queue_id,
            h->mode_effective,
            nerr,
            sizeof(nerr)
        );
        if (h->ctx_handle <= 0) {
            _release_handle_refs(h);
            free(h);
            _err_set(err, 15, nerr[0] ? nerr : "xdp_native_create_failed");
            return NULL;
        }
        h->initialized = 1;
        _err_set(err, 0, "");
        return h;
    }

    h->fn_create = PyObject_GetAttrString(h->xdp_mod, "xdp_create");
    h->fn_destroy = PyObject_GetAttrString(h->xdp_mod, "xdp_destroy");
    if (h->fn_create && PyCallable_Check(h->fn_create) &&
        h->fn_destroy && PyCallable_Check(h->fn_destroy) &&
        PyObject_HasAttrString(h->xdp_mod, "xdp_send_buffer_ctx") &&
        PyObject_HasAttrString(h->xdp_mod, "xdp_send_ctx") &&
        PyObject_HasAttrString(h->xdp_mod, "xdp_stats_ctx")) {
        h->use_ctx_api = 1;
        h->fn_send_buffer = PyObject_GetAttrString(h->xdp_mod, "xdp_send_buffer_ctx");
        h->fn_send = PyObject_GetAttrString(h->xdp_mod, "xdp_send_ctx");
        h->fn_stats = PyObject_GetAttrString(h->xdp_mod, "xdp_stats_ctx");
    } else {
        PyErr_Clear();
        h->use_ctx_api = 0;
        Py_XDECREF(h->fn_create); h->fn_create = NULL;
        Py_XDECREF(h->fn_destroy); h->fn_destroy = NULL;
        h->fn_init = PyObject_GetAttrString(h->xdp_mod, "xdp_init");
        h->fn_send_buffer = PyObject_GetAttrString(h->xdp_mod, "xdp_send_buffer");
        h->fn_send = PyObject_GetAttrString(h->xdp_mod, "xdp_send");
        h->fn_stats = PyObject_GetAttrString(h->xdp_mod, "xdp_stats");
        h->fn_cleanup = PyObject_GetAttrString(h->xdp_mod, "xdp_cleanup");
    }

    if (h->use_ctx_api) {
        if (!h->fn_send_buffer || !PyCallable_Check(h->fn_send_buffer) ||
            !h->fn_send || !PyCallable_Check(h->fn_send) ||
            !h->fn_stats || !PyCallable_Check(h->fn_stats)) {
            _release_handle_refs(h);
            free(h);
            _err_set(err, 13, "xdp_sender context API missing callable methods");
            return NULL;
        }
    } else {
        if (!h->fn_init || !PyCallable_Check(h->fn_init) ||
            !h->fn_send_buffer || !PyCallable_Check(h->fn_send_buffer) ||
            !h->fn_send || !PyCallable_Check(h->fn_send) ||
            !h->fn_stats || !PyCallable_Check(h->fn_stats) ||
            !h->fn_cleanup || !PyCallable_Check(h->fn_cleanup)) {
            _release_handle_refs(h);
            free(h);
            _err_set(err, 13, "xdp_sender required API missing");
            return NULL;
        }
    }

    if (h->mode_requested == 2) {
        if (xdp_core_probe_mode2(cfg->interface, &probe, NULL) == 0) {
            (void)snprintf(h->mode2_probe_status, sizeof(h->mode2_probe_status), "%s", probe.status);
            (void)snprintf(h->mode2_probe_reason, sizeof(h->mode2_probe_reason), "%s", probe.reason);
        } else {
            (void)snprintf(h->mode2_probe_status, sizeof(h->mode2_probe_status), "%s", "unknown");
            (void)snprintf(h->mode2_probe_reason, sizeof(h->mode2_probe_reason), "%s", "probe_unavailable");
        }

        if (hard_policy && strcmp(h->mode2_probe_status, "supported") != 0) {
            char msg[160];
            (void)snprintf(
                msg, sizeof(msg),
                "xdp_mode2_hard_probe_not_supported: %s",
                h->mode2_probe_reason
            );
            _release_handle_refs(h);
            free(h);
            _err_set(err, 14, msg);
            return NULL;
        }
        if (!hard_policy &&
            (strcmp(h->mode2_probe_status, "unsupported") == 0 ||
             strcmp(h->mode2_probe_status, "unknown") == 0)) {
            h->mode_effective = 1;
        }
    }

    if (h->use_ctx_api) {
        ret = PyObject_CallFunction(
            h->fn_create,
            "sii",
            cfg->interface,
            cfg->queue_id,
            h->mode_effective
        );
    } else {
        ret = PyObject_CallFunction(
            h->fn_init,
            "sii",
            cfg->interface,
            cfg->queue_id,
            h->mode_effective
        );
    }
    if (!ret) {
        PyErr_Clear();
        _release_handle_refs(h);
        free(h);
        _err_set(err, 15, "xdp_init_failed");
        return NULL;
    }

    if (h->use_ctx_api) {
        long handle = PyLong_AsLong(ret);
        Py_DECREF(ret);
        if (PyErr_Occurred()) {
            PyErr_Clear();
            _release_handle_refs(h);
            free(h);
            _err_set(err, 16, "xdp_create_handle_invalid");
            return NULL;
        }
        if (handle <= 0) {
            _release_handle_refs(h);
            free(h);
            _err_set(err, 16, "xdp_create_rejected");
            return NULL;
        }
        h->ctx_handle = (int)handle;
    } else {
        if (!PyObject_IsTrue(ret)) {
            Py_DECREF(ret);
            _release_handle_refs(h);
            free(h);
            _err_set(err, 16, "xdp_init_rejected");
            return NULL;
        }
        Py_DECREF(ret);
    }

    h->initialized = 1;
    _err_set(err, 0, "");
    return h;
}

int xdp_core_send_buffer(
    xdp_core_handle *h,
    const uint8_t *buf,
    int pkt_size,
    int count,
    xdp_core_err *err
) {
    PyObject *mv = NULL;
    PyObject *ret = NULL;
    long sent = 0;
    Py_ssize_t nbytes;
    char nerr[160];

    if (!h || !h->xdp_mod || !h->initialized) {
        _err_set(err, 20, "xdp_core handle not initialized");
        return -1;
    }
    if (!buf || pkt_size <= 0 || count <= 0) {
        _err_set(err, 21, "invalid buffer arguments");
        return -1;
    }

    if (h->use_native_api && h->native_api) {
        nerr[0] = '\0';
        sent = (long)h->native_api->send_buffer(
            h->ctx_handle,
            buf,
            pkt_size,
            count,
            nerr,
            sizeof(nerr)
        );
        if (sent < 0) {
            _err_set(err, 23, nerr[0] ? nerr : "xdp_native_send_failed");
            return -1;
        }
        if (sent > count) sent = count;
        _err_set(err, 0, "");
        return (int)sent;
    }

    nbytes = (Py_ssize_t)pkt_size * (Py_ssize_t)count;
    mv = PyMemoryView_FromMemory((char *)buf, nbytes, PyBUF_READ);
    if (!mv) {
        _err_set(err, 22, "memoryview allocation failed");
        return -1;
    }

    if (h->use_ctx_api) {
        ret = PyObject_CallFunction(h->fn_send_buffer, "iOii", h->ctx_handle, mv, pkt_size, count);
    } else {
        ret = PyObject_CallFunction(h->fn_send_buffer, "Oii", mv, pkt_size, count);
    }
    Py_DECREF(mv);
    if (!ret) {
        PyErr_Clear();
        _err_set(err, 23, "xdp_send_failed");
        return -1;
    }

    sent = PyLong_AsLong(ret);
    Py_DECREF(ret);
    if (PyErr_Occurred()) {
        PyErr_Clear();
        _err_set(err, 24, "xdp_send_result_invalid");
        return -1;
    }
    if (sent < 0) sent = 0;
    if (sent > count) sent = count;

    _err_set(err, 0, "");
    return (int)sent;
}

int xdp_core_send_vector(
    xdp_core_handle *h,
    const uint8_t **pkts,
    const uint16_t *lens,
    int count,
    xdp_core_err *err
) {
    PyObject *lst = NULL;
    PyObject *ret = NULL;
    long sent = 0;
    int i;
    char nerr[160];

    if (!h || !h->xdp_mod || !h->initialized) {
        _err_set(err, 30, "xdp_core handle not initialized");
        return -1;
    }
    if (!pkts || !lens || count <= 0) {
        _err_set(err, 31, "invalid vector arguments");
        return -1;
    }

    if (h->use_native_api && h->native_api) {
        nerr[0] = '\0';
        sent = (long)h->native_api->send_vector(
            h->ctx_handle,
            pkts,
            lens,
            count,
            nerr,
            sizeof(nerr)
        );
        if (sent < 0) {
            _err_set(err, 34, nerr[0] ? nerr : "xdp_native_send_failed");
            return -1;
        }
        if (sent > count) sent = count;
        _err_set(err, 0, "");
        return (int)sent;
    }

    lst = PyList_New((Py_ssize_t)count);
    if (!lst) {
        _err_set(err, 32, "list allocation failed");
        return -1;
    }
    for (i = 0; i < count; i++) {
        PyObject *b = PyBytes_FromStringAndSize((const char *)pkts[i], (Py_ssize_t)lens[i]);
        if (!b) {
            Py_DECREF(lst);
            _err_set(err, 33, "packet copy allocation failed");
            return -1;
        }
        PyList_SET_ITEM(lst, i, b); /* steals */
    }

    if (h->use_ctx_api) {
        ret = PyObject_CallFunction(h->fn_send, "iO", h->ctx_handle, lst);
    } else {
        ret = PyObject_CallFunction(h->fn_send, "O", lst);
    }
    Py_DECREF(lst);
    if (!ret) {
        PyErr_Clear();
        _err_set(err, 34, "xdp_send_failed");
        return -1;
    }
    sent = PyLong_AsLong(ret);
    Py_DECREF(ret);
    if (PyErr_Occurred()) {
        PyErr_Clear();
        _err_set(err, 35, "xdp_send_result_invalid");
        return -1;
    }
    if (sent < 0) sent = 0;
    if (sent > count) sent = count;

    _err_set(err, 0, "");
    return (int)sent;
}

int xdp_core_stats(xdp_core_handle *h, xdp_core_stats_snapshot *out, xdp_core_err *err) {
    PyObject *ret = NULL;
    long v = 0;
    xdp_native_stats nstats;
    char nerr[160];

    if (!out) {
        _err_set(err, 40, "stats output is null");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    if (!h || !h->xdp_mod) {
        _err_set(err, 41, "xdp_core handle not initialized");
        return -1;
    }

    if (h->use_native_api && h->native_api) {
        nerr[0] = '\0';
        if (h->native_api->get_stats(h->ctx_handle, &nstats, nerr, sizeof(nerr)) < 0) {
            _err_set(err, 42, nerr[0] ? nerr : "xdp_native_stats_failed");
            return -1;
        }
        out->tx_packets = nstats.tx_packets;
        out->tx_bytes = nstats.tx_bytes;
        out->tx_errors = nstats.tx_errors;
        out->tx_wakeups = nstats.tx_wakeups;
        _err_set(err, 0, "");
        return 0;
    }

    if (h->use_ctx_api) {
        ret = PyObject_CallFunction(h->fn_stats, "i", h->ctx_handle);
    } else {
        ret = PyObject_CallNoArgs(h->fn_stats);
    }
    if (!ret) {
        PyErr_Clear();
        _err_set(err, 42, "xdp_stats_failed");
        return -1;
    }
    if (!PyDict_Check(ret)) {
        Py_DECREF(ret);
        _err_set(err, 43, "xdp_stats_invalid");
        return -1;
    }

    (void)_as_long(ret, "tx_packets", &v); out->tx_packets = (uint64_t)(v < 0 ? 0 : v);
    (void)_as_long(ret, "tx_bytes", &v); out->tx_bytes = (uint64_t)(v < 0 ? 0 : v);
    (void)_as_long(ret, "tx_errors", &v); out->tx_errors = (uint64_t)(v < 0 ? 0 : v);
    (void)_as_long(ret, "tx_wakeups", &v); out->tx_wakeups = (uint64_t)(v < 0 ? 0 : v);
    Py_DECREF(ret);

    _err_set(err, 0, "");
    return 0;
}

int xdp_core_close(xdp_core_handle *h, xdp_core_err *err) {
    PyObject *ret = NULL;
    char nerr[160];

    if (!h) {
        _err_set(err, 0, "");
        return 0;
    }
    if (h->initialized) {
        if (h->use_native_api && h->native_api) {
            nerr[0] = '\0';
            (void)h->native_api->destroy_ctx(h->ctx_handle, nerr, sizeof(nerr));
        } else if (h->use_ctx_api) {
            if (h->fn_destroy) {
                ret = PyObject_CallFunction(h->fn_destroy, "i", h->ctx_handle);
            }
        } else if (h->fn_cleanup) {
            ret = PyObject_CallNoArgs(h->fn_cleanup);
        }
        if (!ret) {
            PyErr_Clear();
        } else {
            Py_DECREF(ret);
        }
        h->initialized = 0;
    }
    _release_handle_refs(h);
    free(h);
    _err_set(err, 0, "");
    return 0;
}

int xdp_core_mode_requested(const xdp_core_handle *h) {
    return h ? h->mode_requested : 0;
}

int xdp_core_mode_effective(const xdp_core_handle *h) {
    return h ? h->mode_effective : 0;
}

const char *xdp_core_mode2_policy(const xdp_core_handle *h) {
    return h ? h->mode2_policy : "soft";
}

const char *xdp_core_mode2_probe_status(const xdp_core_handle *h) {
    return h ? h->mode2_probe_status : "not_run";
}

const char *xdp_core_mode2_probe_reason(const xdp_core_handle *h) {
    return h ? h->mode2_probe_reason : "not_run";
}
