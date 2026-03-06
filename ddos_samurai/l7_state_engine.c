#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef SAMURAI_WITH_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#ifdef SAMURAI_WITH_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_NGHTTP3)
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>
#endif

typedef struct {
    long id;
    long runs_total;
    long sessions_total;
    long sessions_ok;
    long sessions_err;
    long last_attempted;
    long last_sent;
    long last_errors;
    long last_retry_attempts;
    long last_retry_successes;
    long last_active_sessions_peak;
    double last_conn_rate;
    double last_handshake_p99_ms;
    int closed;
} L7Handle;

typedef enum {
    SESSION_CONNECTING = 1,
    SESSION_TLS_HANDSHAKE = 2,
    SESSION_SENDING = 3,
    SESSION_READING = 4,
    SESSION_WEBSOCKET_SCENARIO = 5
} SessionState;

typedef struct {
    int in_use;
    int fd;
    int use_tls;
    SessionState state;
    size_t req_len;
    size_t req_off;
    size_t resp_len;
    char req[1024];
    char resp[2048];
    long long start_ns;
    long long deadline_ns;
    int ws_scenario_enabled;
    int ws_await_response;
    int ws_step_index;
    int ws_total_steps;
    int ws_waiting_response;
    size_t ws_frame_len;
    size_t ws_frame_off;
    unsigned char ws_frame[512];
    size_t ws_recv_len;
    unsigned char ws_recv[1024];
#ifdef SAMURAI_WITH_OPENSSL
    SSL *ssl;
    size_t tls_pending_len;
    size_t tls_pending_off;
    unsigned char tls_pending[8192];
#endif
} Session;

typedef struct {
    int enabled;
    int verify_peer;
    const char *server_name;
#ifdef SAMURAI_WITH_OPENSSL
    SSL_CTX *ctx;
#endif
} TlsConfig;

#define WS_MAX_SUBSCRIBE_MESSAGES 16
#define WS_MAX_MESSAGE_LEN 192
#define H2_PLAN_METHOD_MAX_LEN 24
#define H2_PLAN_PATH_MAX_LEN 512
#define H2_PLAN_UA_MAX_LEN 256

typedef struct {
    int enabled;
    int await_response;
    int subscribe_count;
    int ping_count;
    int total_steps;
    char auth_message[WS_MAX_MESSAGE_LEN];
    char ping_message[WS_MAX_MESSAGE_LEN];
    char subscribe_messages[WS_MAX_SUBSCRIBE_MESSAGES][WS_MAX_MESSAGE_LEN];
} WsScenarioConfig;

static long g_l7_next_id = 1;

static long long monotonic_ns_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return ((long long)ts.tv_sec * 1000000000LL) + (long long)ts.tv_nsec;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    return 0;
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

static int _set_double(PyObject *dict, const char *key, double value) {
    PyObject *v = PyFloat_FromDouble(value);
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

static double _dict_double(PyObject *cfg, const char *key, double fallback) {
    PyObject *v;
    if (!PyDict_Check(cfg)) {
        return fallback;
    }
    v = PyDict_GetItemString(cfg, key);
    if (v == NULL) {
        return fallback;
    }
    if (PyFloat_Check(v)) {
        return PyFloat_AsDouble(v);
    }
    if (PyLong_Check(v)) {
        return (double)PyLong_AsLong(v);
    }
    return fallback;
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

static char *_dup_limited_cstr(const char *src, size_t max_len) {
    size_t n = 0;
    char *out = NULL;
    if (src == NULL || src[0] == '\0' || max_len == 0) {
        return NULL;
    }
    while (n < max_len && src[n] != '\0') {
        n += 1;
    }
    if (n == 0) {
        return NULL;
    }
    out = (char *)PyMem_Malloc(n + 1);
    if (out == NULL) {
        PyErr_NoMemory();
        return NULL;
    }
    memcpy(out, src, n);
    out[n] = '\0';
    return out;
}

static char **_cfg_string_plan(
    PyObject *cfg,
    const char *key,
    long expected_count,
    size_t max_len,
    long *used_out
) {
    PyObject *raw = NULL;
    PyObject *seq = NULL;
    Py_ssize_t seq_len = 0;
    Py_ssize_t limit = 0;
    char **out = NULL;
    long used = 0;

    if (used_out != NULL) {
        *used_out = 0;
    }
    if (!PyDict_Check(cfg) || key == NULL || expected_count <= 0 || max_len == 0) {
        return NULL;
    }

    raw = PyDict_GetItemString(cfg, key);
    if (raw == NULL) {
        return NULL;
    }
    seq = PySequence_Fast(raw, "sequence expected");
    if (seq == NULL) {
        PyErr_Clear();
        return NULL;
    }

    seq_len = PySequence_Fast_GET_SIZE(seq);
    if (seq_len <= 0) {
        Py_DECREF(seq);
        return NULL;
    }

    out = (char **)PyMem_Calloc((size_t)expected_count, sizeof(char *));
    if (out == NULL) {
        Py_DECREF(seq);
        PyErr_NoMemory();
        return NULL;
    }

    limit = seq_len;
    if ((long)limit > expected_count) {
        limit = (Py_ssize_t)expected_count;
    }

    for (Py_ssize_t i = 0; i < limit; i++) {
        PyObject *item = PySequence_Fast_GET_ITEM(seq, i);
        const char *s = NULL;
        if (item == NULL || !PyUnicode_Check(item)) {
            continue;
        }
        s = PyUnicode_AsUTF8(item);
        if (s == NULL || s[0] == '\0') {
            PyErr_Clear();
            continue;
        }
        out[i] = _dup_limited_cstr(s, max_len);
        if (out[i] == NULL) {
            if (PyErr_Occurred()) {
                for (Py_ssize_t j = 0; j < i; j++) {
                    PyMem_Free(out[j]);
                }
                PyMem_Free(out);
                Py_DECREF(seq);
                return NULL;
            }
            continue;
        }
        used += 1;
    }
    Py_DECREF(seq);
    if (used_out != NULL) {
        *used_out = used;
    }
    return out;
}

static void _free_string_plan(char **plan, long count) {
    if (plan == NULL || count <= 0) {
        return;
    }
    for (long i = 0; i < count; i++) {
        PyMem_Free(plan[i]);
    }
    PyMem_Free(plan);
}

static void _copy_upper_ascii(char *dst, size_t dst_len, const char *src, const char *fallback) {
    size_t i;
    const char *s = src;
    if (dst == NULL || dst_len == 0) {
        return;
    }
    if (s == NULL || s[0] == '\0') {
        s = fallback != NULL ? fallback : "GET";
    }
    for (i = 0; i + 1 < dst_len && s[i] != '\0'; i++) {
        dst[i] = (char)toupper((unsigned char)s[i]);
    }
    dst[i] = '\0';
}

static int _scheme_is_tls(const char *scheme) {
    if (scheme == NULL || scheme[0] == '\0') {
        return 0;
    }
    return strcmp(scheme, "https") == 0 || strcmp(scheme, "wss") == 0;
}

static int _is_ipv4_literal(const char *value) {
    struct in_addr tmp;
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    return inet_pton(AF_INET, value, &tmp) == 1;
}

#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_NGHTTP3)
typedef struct {
    int checked;
    int available;
    const char *reason;
} QuicStackProbeState;

static QuicStackProbeState g_quic_stack_probe = {0, 0, "not_checked"};

static int _quic_stack_probe(const char **reason_out) {
    const ngtcp2_info *ngtcp2_info_ptr = NULL;
    const nghttp3_info *nghttp3_info_ptr = NULL;
    const char *reason = "ok";
    int available = 0;

    if (g_quic_stack_probe.checked) {
        if (reason_out != NULL) {
            *reason_out = g_quic_stack_probe.reason;
        }
        return g_quic_stack_probe.available;
    }

    ngtcp2_info_ptr = ngtcp2_version(0);
    if (ngtcp2_info_ptr == NULL) {
        reason = "ngtcp2_version_unavailable";
        goto done;
    }

    nghttp3_info_ptr = nghttp3_version(0);
    if (nghttp3_info_ptr == NULL) {
        reason = "nghttp3_version_unavailable";
        goto done;
    }

    if (!ngtcp2_is_supported_version((uint32_t)0x00000001u)) {
        reason = "ngtcp2_quic_v1_unsupported";
        goto done;
    }

    available = 1;

done:
    g_quic_stack_probe.checked = 1;
    g_quic_stack_probe.available = available;
    g_quic_stack_probe.reason = reason;
    if (reason_out != NULL) {
        *reason_out = reason;
    }
    return available;
}
#endif

#ifdef SAMURAI_WITH_OPENSSL
static int g_ssl_global_init_done = 0;

static int _ssl_global_init(void) {
    if (g_ssl_global_init_done) {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        return -1;
    }
#endif
    g_ssl_global_init_done = 1;
    return 0;
}

static SSL_CTX *_tls_ctx_create_with_alpn(
    int verify_peer,
    const unsigned char *alpn,
    size_t alpn_len,
    const char **reason_out
) {
    SSL_CTX *ctx = NULL;

    if (reason_out != NULL) {
        *reason_out = "tls_ctx_create_failed";
    }
    if (_ssl_global_init() < 0) {
        if (reason_out != NULL) {
            *reason_out = "tls_init_failed";
        }
        return NULL;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        if (reason_out != NULL) {
            *reason_out = "tls_ctx_create_failed";
        }
        return NULL;
    }

#ifdef TLS1_2_VERSION
    (void)SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#endif
#ifdef SSL_OP_NO_KTLS
    /* Userspace TLS keeps behavior stable across kernels/runners. */
    SSL_CTX_set_options(ctx, SSL_OP_NO_KTLS);
#endif
#ifdef SSL_OP_ENABLE_KTLS
    /* Some OpenSSL builds expose ENABLE-only semantics; force-disable kernel TLS. */
    SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_KTLS);
#endif

    if (alpn != NULL && alpn_len > 0) {
        (void)SSL_CTX_set_alpn_protos(ctx, alpn, (unsigned int)alpn_len);
    }

    if (verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            if (reason_out != NULL) {
                *reason_out = "tls_verify_store_unavailable";
            }
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    if (reason_out != NULL) {
        *reason_out = "none";
    }
    return ctx;
}

static SSL_CTX *_tls_ctx_create(int verify_peer, const char **reason_out) {
    static const unsigned char alpn_http11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    return _tls_ctx_create_with_alpn(verify_peer, alpn_http11, sizeof(alpn_http11), reason_out);
}
#endif

static int _cmp_longlong(const void *a, const void *b) {
    long long av = *(const long long *)a;
    long long bv = *(const long long *)b;
    if (av < bv) {
        return -1;
    }
    if (av > bv) {
        return 1;
    }
    return 0;
}

static int _parse_http_status(const char *buf, size_t len) {
    size_t line_end = 0;
    size_t i;
    const char *sp;

    if (buf == NULL || len < 12) {
        return -1;
    }

    for (i = 0; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            line_end = i;
            break;
        }
    }
    if (line_end == 0) {
        return -1;
    }
    if (line_end < 12) {
        return -1;
    }
    if (strncmp(buf, "HTTP/", 5) != 0) {
        return -1;
    }

    sp = memchr(buf, ' ', line_end);
    if (sp == NULL || (sp + 3) >= (buf + line_end)) {
        return -1;
    }
    if (!isdigit((unsigned char)sp[1]) ||
        !isdigit((unsigned char)sp[2]) ||
        !isdigit((unsigned char)sp[3])) {
        return -1;
    }

    return ((sp[1] - '0') * 100) + ((sp[2] - '0') * 10) + (sp[3] - '0');
}

static void _copy_bounded_cstr(char *dst, size_t dst_len, const char *src, const char *fallback) {
    size_t i = 0;
    const char *s = src;
    if (dst == NULL || dst_len == 0) {
        return;
    }
    if (s == NULL || s[0] == '\0') {
        s = fallback != NULL ? fallback : "";
    }
    for (i = 0; i + 1 < dst_len && s[i] != '\0'; i++) {
        dst[i] = s[i];
    }
    dst[i] = '\0';
}

static int _http_headers_complete(const char *buf, size_t len, size_t *header_end_out) {
    size_t i;
    if (buf == NULL || len < 4) {
        return 0;
    }
    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            if (header_end_out != NULL) {
                *header_end_out = i + 4;
            }
            return 1;
        }
    }
    return 0;
}

static int _ws_parse_subscribe_messages(WsScenarioConfig *cfg, const char *raw, long requested_count) {
    const char *cursor;
    int parsed = 0;
    if (cfg == NULL) {
        return 0;
    }
    if (requested_count < 0) {
        requested_count = 0;
    }
    if (requested_count > WS_MAX_SUBSCRIBE_MESSAGES) {
        requested_count = WS_MAX_SUBSCRIBE_MESSAGES;
    }

    cursor = raw;
    while (cursor != NULL && cursor[0] != '\0' && parsed < WS_MAX_SUBSCRIBE_MESSAGES) {
        const char *sep = strchr(cursor, '\x1f');
        size_t len = sep != NULL ? (size_t)(sep - cursor) : strlen(cursor);
        if (len > 0) {
            size_t cap = sizeof(cfg->subscribe_messages[parsed]);
            if (len >= cap) {
                len = cap - 1;
            }
            memcpy(cfg->subscribe_messages[parsed], cursor, len);
            cfg->subscribe_messages[parsed][len] = '\0';
            parsed += 1;
        }
        if (sep == NULL) {
            break;
        }
        cursor = sep + 1;
    }

    while (parsed < requested_count && parsed < WS_MAX_SUBSCRIBE_MESSAGES) {
        _copy_bounded_cstr(cfg->subscribe_messages[parsed], sizeof(cfg->subscribe_messages[parsed]), "subscribe", "subscribe");
        parsed += 1;
    }
    cfg->subscribe_count = parsed;
    return parsed;
}

static const char *_ws_step_message(const WsScenarioConfig *cfg, int step_index) {
    int idx = step_index;
    int has_auth;
    if (cfg == NULL || idx < 0) {
        return NULL;
    }
    has_auth = cfg->auth_message[0] != '\0';
    if (has_auth) {
        if (idx == 0) {
            return cfg->auth_message;
        }
        idx -= 1;
    }
    if (idx < cfg->subscribe_count) {
        return cfg->subscribe_messages[idx];
    }
    idx -= cfg->subscribe_count;
    if (idx < cfg->ping_count) {
        return cfg->ping_message;
    }
    return NULL;
}

static int _ws_build_text_frame(unsigned char *dst, size_t cap, const char *message, uint32_t mask_seed) {
    size_t payload_len;
    size_t idx = 0;
    unsigned char mask[4];
    if (dst == NULL || cap < 6) {
        return -1;
    }
    if (message == NULL) {
        message = "";
    }
    payload_len = strlen(message);
    if (payload_len > 65535) {
        return -1;
    }

    dst[idx++] = 0x81; /* FIN + text frame */
    if (payload_len < 126) {
        dst[idx++] = (unsigned char)(0x80 | payload_len);
    } else {
        dst[idx++] = 0x80 | 126;
        dst[idx++] = (unsigned char)((payload_len >> 8) & 0xFF);
        dst[idx++] = (unsigned char)(payload_len & 0xFF);
    }

    mask[0] = (unsigned char)(mask_seed & 0xFF);
    mask[1] = (unsigned char)((mask_seed >> 8) & 0xFF);
    mask[2] = (unsigned char)((mask_seed >> 16) & 0xFF);
    mask[3] = (unsigned char)((mask_seed >> 24) & 0xFF);
    if (mask[0] == 0 && mask[1] == 0 && mask[2] == 0 && mask[3] == 0) {
        mask[0] = 0xA5;
        mask[1] = 0x5A;
        mask[2] = 0x11;
        mask[3] = 0x77;
    }

    if (idx + 4 + payload_len > cap) {
        return -1;
    }
    memcpy(dst + idx, mask, 4);
    idx += 4;

    for (size_t i = 0; i < payload_len; i++) {
        dst[idx + i] = ((const unsigned char *)message)[i] ^ mask[i & 3];
    }
    idx += payload_len;
    return (int)idx;
}

static int _ws_next_frame_consumed(const unsigned char *buf, size_t len, size_t *consumed_out) {
    size_t pos = 2;
    uint64_t payload_len;
    int masked;

    if (buf == NULL || len < 2) {
        return 0;
    }

    masked = (buf[1] & 0x80) ? 1 : 0;
    payload_len = (uint64_t)(buf[1] & 0x7F);
    if (payload_len == 126) {
        if (len < 4) {
            return 0;
        }
        payload_len = ((uint64_t)buf[2] << 8) | (uint64_t)buf[3];
        pos = 4;
    } else if (payload_len == 127) {
        if (len < 10) {
            return 0;
        }
        payload_len =
            ((uint64_t)buf[2] << 56) |
            ((uint64_t)buf[3] << 48) |
            ((uint64_t)buf[4] << 40) |
            ((uint64_t)buf[5] << 32) |
            ((uint64_t)buf[6] << 24) |
            ((uint64_t)buf[7] << 16) |
            ((uint64_t)buf[8] << 8) |
            (uint64_t)buf[9];
        pos = 10;
    }

    if (masked) {
        if (len < pos + 4) {
            return 0;
        }
        pos += 4;
    }
    if (payload_len > (uint64_t)(SIZE_MAX - pos)) {
        return -1;
    }
    if (len < pos + (size_t)payload_len) {
        return 0;
    }
    if (consumed_out != NULL) {
        *consumed_out = pos + (size_t)payload_len;
    }
    return 1;
}

static int _ws_consume_one_frame(Session *s) {
    size_t consumed = 0;
    int rc;
    if (s == NULL) {
        return -1;
    }
    rc = _ws_next_frame_consumed(s->ws_recv, s->ws_recv_len, &consumed);
    if (rc <= 0) {
        return rc;
    }
    if (consumed >= s->ws_recv_len) {
        s->ws_recv_len = 0;
        return 1;
    }
    memmove(s->ws_recv, s->ws_recv + consumed, s->ws_recv_len - consumed);
    s->ws_recv_len -= consumed;
    return 1;
}

static int _build_request(
    Session *s,
    const char *target_ip,
    int target_port,
    const char *path,
    const char *http_method,
    int websocket_mode
) {
    int n;

    if (s == NULL) {
        return -1;
    }

    if (path == NULL || path[0] == '\0') {
        path = "/";
    }

    if (websocket_mode) {
        n = snprintf(
            s->req,
            sizeof(s->req),
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: c2FtdXJhaS1zdGF0ZS1rZXk=\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: DDoSamurai-L7/1.0\r\n"
            "\r\n",
            path,
            target_ip,
            target_port
        );
    } else {
        if (http_method == NULL || http_method[0] == '\0') {
            http_method = "GET";
        }
        n = snprintf(
            s->req,
            sizeof(s->req),
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: close\r\n"
            "User-Agent: DDoSamurai-L7/1.0\r\n"
            "\r\n",
            http_method,
            path,
            target_ip,
            target_port
        );
    }

    if (n < 0 || (size_t)n >= sizeof(s->req)) {
        return -1;
    }

    s->req_len = (size_t)n;
    s->req_off = 0;
    s->resp_len = 0;
    return 0;
}

static void _session_release(int epfd, Session *s) {
    if (s == NULL) {
        return;
    }
#ifdef SAMURAI_WITH_OPENSSL
    if (s->ssl != NULL) {
        SSL_free(s->ssl);
        s->ssl = NULL;
    }
#endif
    if (s->fd >= 0) {
        (void)epoll_ctl(epfd, EPOLL_CTL_DEL, s->fd, NULL);
        close(s->fd);
    }
    memset(s, 0, sizeof(*s));
    s->fd = -1;
}

#ifdef SAMURAI_WITH_OPENSSL
static int _session_attach_tls(Session *s, const TlsConfig *tls_cfg) {
    BIO *rbio = NULL;
    BIO *wbio = NULL;

    if (s == NULL || tls_cfg == NULL || !tls_cfg->enabled || tls_cfg->ctx == NULL) {
        return -1;
    }
    if (s->ssl != NULL) {
        return 0;
    }

    s->ssl = SSL_new(tls_cfg->ctx);
    if (s->ssl == NULL) {
        return -1;
    }

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (rbio == NULL || wbio == NULL) {
        if (rbio != NULL) {
            BIO_free(rbio);
        }
        if (wbio != NULL) {
            BIO_free(wbio);
        }
        SSL_free(s->ssl);
        s->ssl = NULL;
        return -1;
    }
    SSL_set_bio(s->ssl, rbio, wbio);
#ifdef SSL_OP_NO_KTLS
    (void)SSL_set_options(s->ssl, SSL_OP_NO_KTLS);
#endif
#ifdef SSL_OP_ENABLE_KTLS
    (void)SSL_clear_options(s->ssl, SSL_OP_ENABLE_KTLS);
#endif
    SSL_set_connect_state(s->ssl);
    if (tls_cfg->server_name != NULL &&
        tls_cfg->server_name[0] != '\0' &&
        !_is_ipv4_literal(tls_cfg->server_name)) {
        (void)SSL_set_tlsext_host_name(s->ssl, tls_cfg->server_name);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        if (tls_cfg->verify_peer) {
            (void)SSL_set1_host(s->ssl, tls_cfg->server_name);
        }
#endif
    }
    return 0;
}

static int _tls_flush_socket(Session *s) {
    BIO *wbio;
    unsigned char scratch[4096];

    if (s == NULL || s->ssl == NULL) {
        return -1;
    }
    wbio = SSL_get_wbio(s->ssl);
    if (wbio == NULL) {
        return -1;
    }

    for (;;) {
        while (s->tls_pending_off < s->tls_pending_len) {
            ssize_t wr = send(
                s->fd,
                s->tls_pending + s->tls_pending_off,
                s->tls_pending_len - s->tls_pending_off,
                MSG_NOSIGNAL
            );
            if (wr > 0) {
                s->tls_pending_off += (size_t)wr;
                continue;
            }
            if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return 0;
            }
            return -1;
        }

        s->tls_pending_off = 0;
        s->tls_pending_len = 0;

        for (;;) {
            int rd = BIO_read(wbio, scratch, (int)sizeof(scratch));
            if (rd > 0) {
                size_t copy_len = (size_t)rd;
                if (copy_len > sizeof(s->tls_pending)) {
                    copy_len = sizeof(s->tls_pending);
                }
                memcpy(s->tls_pending, scratch, copy_len);
                s->tls_pending_len = copy_len;
                break;
            }
            if (rd == 0) {
                return 1;
            }
            if (BIO_should_retry(wbio)) {
                return 1;
            }
            return -1;
        }
    }
}

static int _tls_feed_socket(Session *s) {
    BIO *rbio;
    unsigned char buf[4096];

    if (s == NULL || s->ssl == NULL) {
        return -1;
    }
    rbio = SSL_get_rbio(s->ssl);
    if (rbio == NULL) {
        return -1;
    }

    for (;;) {
        ssize_t n = recv(s->fd, buf, sizeof(buf), 0);
        if (n > 0) {
            int bw = BIO_write(rbio, buf, (int)n);
            if (bw <= 0) {
                return -1;
            }
            continue;
        }
        if (n == 0) {
            return 0;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
}
#endif

static int _session_start(
    Session *s,
    int epfd,
    const struct sockaddr_in *addr,
    long long now_ns,
    long long timeout_ns,
    const char *target_ip,
    int target_port,
    const char *path,
    const char *http_method,
    int websocket_mode,
    const TlsConfig *tls_cfg,
    const WsScenarioConfig *ws_cfg
) {
    int fd;
    int rc;
    struct epoll_event ev;

    memset(s, 0, sizeof(*s));
    s->fd = -1;

    if (_build_request(s, target_ip, target_port, path, http_method, websocket_mode) < 0) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (set_nonblocking(fd) < 0) {
        close(fd);
        return -1;
    }

    rc = connect(fd, (const struct sockaddr *)addr, sizeof(*addr));
    s->fd = fd;
    if (rc == 0) {
        s->state = SESSION_SENDING;
    } else {
        if (errno != EINPROGRESS) {
            close(fd);
            return -1;
        }
        s->state = SESSION_CONNECTING;
    }

    if (tls_cfg != NULL && tls_cfg->enabled) {
        s->use_tls = 1;
    }

    if (s->use_tls && s->state == SESSION_SENDING) {
#ifdef SAMURAI_WITH_OPENSSL
        if (_session_attach_tls(s, tls_cfg) < 0) {
            close(fd);
            return -1;
        }
        s->state = SESSION_TLS_HANDSHAKE;
#else
        close(fd);
        return -1;
#endif
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
    ev.data.ptr = s;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(fd);
        return -1;
    }

    s->in_use = 1;
    s->start_ns = now_ns;
    s->deadline_ns = now_ns + timeout_ns;
    s->ws_scenario_enabled = (websocket_mode && ws_cfg != NULL && ws_cfg->enabled) ? 1 : 0;
    s->ws_await_response = s->ws_scenario_enabled ? (ws_cfg->await_response ? 1 : 0) : 0;
    s->ws_total_steps = s->ws_scenario_enabled ? ws_cfg->total_steps : 0;
    s->ws_step_index = 0;
    s->ws_waiting_response = 0;
    s->ws_frame_len = 0;
    s->ws_frame_off = 0;
    s->ws_recv_len = 0;
    return 0;
}

static int _session_socket_send_bytes(Session *s, const unsigned char *buf, size_t len, uint32_t events) {
    ssize_t n;
    if (s == NULL || buf == NULL) {
        return -1;
    }
    while (s->ws_frame_off < len) {
        if (s->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
            if ((events & EPOLLIN) != 0) {
                int fed = _tls_feed_socket(s);
                if (fed < 0) {
                    return -1;
                }
            }
            if (_tls_flush_socket(s) < 0) {
                return -1;
            }
            int wr = SSL_write(s->ssl, buf + s->ws_frame_off, (int)(len - s->ws_frame_off));
            if (_tls_flush_socket(s) < 0) {
                return -1;
            }
            if (wr > 0) {
                s->ws_frame_off += (size_t)wr;
                continue;
            }
            wr = SSL_get_error(s->ssl, wr);
            if (wr == SSL_ERROR_WANT_READ || wr == SSL_ERROR_WANT_WRITE) {
                return 0;
            }
            return -1;
#else
            return -1;
#endif
        } else {
            n = send(s->fd, buf + s->ws_frame_off, len - s->ws_frame_off, MSG_NOSIGNAL);
            if (n > 0) {
                s->ws_frame_off += (size_t)n;
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return 0;
            }
            return -1;
        }
    }
    return 1;
}

static int _session_socket_read_ws(Session *s, uint32_t events) {
    ssize_t n;
    int read_any = 0;
    if (s == NULL) {
        return -1;
    }
    if (s->ws_recv_len >= sizeof(s->ws_recv)) {
        return -1;
    }

    for (;;) {
        if (s->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
            if ((events & EPOLLIN) != 0) {
                int fed = _tls_feed_socket(s);
                if (fed < 0) {
                    return -1;
                }
            }
            if (_tls_flush_socket(s) < 0) {
                return -1;
            }
            int rdret = SSL_read(s->ssl, s->ws_recv + s->ws_recv_len, (int)(sizeof(s->ws_recv) - s->ws_recv_len));
            if (_tls_flush_socket(s) < 0) {
                return -1;
            }
            if (rdret > 0) {
                s->ws_recv_len += (size_t)rdret;
                read_any = 1;
                if (s->ws_recv_len >= sizeof(s->ws_recv)) {
                    return -1;
                }
                continue;
            } else {
                int rd = SSL_get_error(s->ssl, rdret);
                if (rd == SSL_ERROR_WANT_READ || rd == SSL_ERROR_WANT_WRITE) {
                    return read_any ? 1 : 0;
                }
                if (rd == SSL_ERROR_ZERO_RETURN) {
                    return read_any ? 1 : -1;
                }
                return -1;
            }
#else
            return -1;
#endif
        } else {
            n = recv(s->fd, s->ws_recv + s->ws_recv_len, sizeof(s->ws_recv) - s->ws_recv_len, 0);
            if (n > 0) {
                s->ws_recv_len += (size_t)n;
                read_any = 1;
                if (s->ws_recv_len >= sizeof(s->ws_recv)) {
                    return -1;
                }
                continue;
            }
            if (n == 0) {
                return read_any ? 1 : -1;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return read_any ? 1 : 0;
            }
            return -1;
        }
    }
}

static int _session_websocket_scenario_progress(
    Session *s,
    uint32_t events,
    const WsScenarioConfig *ws_cfg
) {
    if (s == NULL || ws_cfg == NULL || !s->ws_scenario_enabled) {
        return 1;
    }
    if (s->ws_total_steps <= 0) {
        return 1;
    }

    for (;;) {
        if (s->ws_step_index >= s->ws_total_steps) {
            return 1;
        }

        if (s->ws_waiting_response) {
            int consume_rc = _ws_consume_one_frame(s);
            if (consume_rc > 0) {
                s->ws_waiting_response = 0;
                s->ws_step_index += 1;
                continue;
            }
            if (consume_rc < 0) {
                return -1;
            }
            int read_rc = _session_socket_read_ws(s, events);
            if (read_rc < 0) {
                return -1;
            }
            if (read_rc == 0) {
                return 0;
            }
            continue;
        }

        if (s->ws_frame_len == 0) {
            const char *msg = _ws_step_message(ws_cfg, s->ws_step_index);
            uint32_t mask_seed = (uint32_t)(monotonic_ns_now() ^ ((long long)s->fd << 16) ^ (long long)s->ws_step_index);
            int frame_len;
            if (msg == NULL) {
                s->ws_step_index = s->ws_total_steps;
                return 1;
            }
            frame_len = _ws_build_text_frame(s->ws_frame, sizeof(s->ws_frame), msg, mask_seed);
            if (frame_len < 0) {
                return -1;
            }
            s->ws_frame_len = (size_t)frame_len;
            s->ws_frame_off = 0;
        }

        {
            int send_rc = _session_socket_send_bytes(s, s->ws_frame, s->ws_frame_len, events);
            if (send_rc < 0) {
                return -1;
            }
            if (send_rc == 0) {
                return 0;
            }
        }

        s->ws_frame_len = 0;
        s->ws_frame_off = 0;
        if (s->ws_await_response) {
            s->ws_waiting_response = 1;
            continue;
        }
        s->ws_step_index += 1;
    }
}

static int _session_progress(
    Session *s,
    uint32_t events,
    int websocket_mode,
    const TlsConfig *tls_cfg,
    const WsScenarioConfig *ws_cfg
) {
    int sock_err = 0;
    socklen_t sock_err_len = sizeof(sock_err);
    ssize_t n;
    int status;

    if (s == NULL || !s->in_use) {
        return 0;
    }

    if ((events & (EPOLLERR | EPOLLHUP)) != 0 && (events & (EPOLLIN | EPOLLOUT)) == 0) {
        return -1;
    }

    for (;;) {
        if (s->state == SESSION_CONNECTING) {
            if ((events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) == 0) {
                return 0;
            }
            if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_err_len) < 0 || sock_err != 0) {
                return -1;
            }
            if (s->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
                if (_session_attach_tls(s, tls_cfg) < 0) {
                    return -1;
                }
                s->state = SESSION_TLS_HANDSHAKE;
#else
                return -1;
#endif
            } else {
                s->state = SESSION_SENDING;
            }
            continue;
        }

        if (s->state == SESSION_TLS_HANDSHAKE) {
#ifdef SAMURAI_WITH_OPENSSL
            if ((events & EPOLLIN) != 0) {
                int fed = _tls_feed_socket(s);
                if (fed < 0) {
                    return -1;
                }
            }
            if (_tls_flush_socket(s) < 0) {
                return -1;
            }
            int rc = SSL_connect(s->ssl);
            if (_tls_flush_socket(s) < 0) {
                return -1;
            }
            if (rc == 1) {
                if (s->tls_pending_off < s->tls_pending_len) {
                    return 0;
                }
                s->state = SESSION_SENDING;
                continue;
            }
            rc = SSL_get_error(s->ssl, rc);
            if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE) {
                return 0;
            }
            return -1;
#else
            return -1;
#endif
        }

        if (s->state == SESSION_SENDING) {
            while (s->req_off < s->req_len) {
                if (s->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
                    if ((events & EPOLLIN) != 0) {
                        int fed = _tls_feed_socket(s);
                        if (fed < 0) {
                            return -1;
                        }
                    }
                    if (_tls_flush_socket(s) < 0) {
                        return -1;
                    }
                    int wr = SSL_write(s->ssl, s->req + s->req_off, (int)(s->req_len - s->req_off));
                    if (_tls_flush_socket(s) < 0) {
                        return -1;
                    }
                    if (wr > 0) {
                        s->req_off += (size_t)wr;
                        if (s->tls_pending_off < s->tls_pending_len) {
                            return 0;
                        }
                        continue;
                    }
                    wr = SSL_get_error(s->ssl, wr);
                    if (wr == SSL_ERROR_WANT_READ || wr == SSL_ERROR_WANT_WRITE) {
                        return 0;
                    }
                    return -1;
#else
                    return -1;
#endif
                } else {
                    n = send(s->fd, s->req + s->req_off, s->req_len - s->req_off, MSG_NOSIGNAL);
                    if (n > 0) {
                        s->req_off += (size_t)n;
                        continue;
                    }
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        return 0;
                    }
                    return -1;
                }
            }
            s->state = SESSION_READING;
            continue;
        }

        if (s->state == SESSION_READING) {
            if (s->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
                if ((events & EPOLLIN) != 0) {
                    int fed = _tls_feed_socket(s);
                    if (fed < 0) {
                        return -1;
                    }
                }
                if (_tls_flush_socket(s) < 0) {
                    return -1;
                }
                int rdret = SSL_read(s->ssl, s->resp + s->resp_len, (int)(sizeof(s->resp) - s->resp_len - 1));
                if (_tls_flush_socket(s) < 0) {
                    return -1;
                }
                if (rdret > 0) {
                    n = (ssize_t)rdret;
                } else {
                    int rd = SSL_get_error(s->ssl, rdret);
                    if (rd == SSL_ERROR_WANT_READ || rd == SSL_ERROR_WANT_WRITE) {
                        return 0;
                    }
                    if (rd == SSL_ERROR_ZERO_RETURN) {
                        status = _parse_http_status(s->resp, s->resp_len);
                        if (status > 0) {
                            if (!websocket_mode) {
                                return 1;
                            }
                            if (status != 101) {
                                return -1;
                            }
                            if (!s->ws_scenario_enabled) {
                                return 1;
                            }
                            {
                                size_t header_end = 0;
                                int headers_done = _http_headers_complete(s->resp, s->resp_len, &header_end);
                                if (!headers_done) {
                                    return -1;
                                }
                                if (s->resp_len > header_end) {
                                    size_t leftover = s->resp_len - header_end;
                                    if (leftover > sizeof(s->ws_recv)) {
                                        return -1;
                                    }
                                    memcpy(s->ws_recv, s->resp + header_end, leftover);
                                    s->ws_recv_len = leftover;
                                }
                            }
                            s->resp_len = 0;
                            s->state = SESSION_WEBSOCKET_SCENARIO;
                            continue;
                        }
                        return -1;
                    }
                    return -1;
                }
#else
                return -1;
#endif
            } else {
                n = recv(s->fd, s->resp + s->resp_len, sizeof(s->resp) - s->resp_len - 1, 0);
            }

            if (n > 0) {
                s->resp_len += (size_t)n;
                s->resp[s->resp_len] = '\0';

                status = _parse_http_status(s->resp, s->resp_len);
                if (status > 0) {
                    if (!websocket_mode) {
                        return 1;
                    }
                    if (status != 101) {
                        return -1;
                    }
                    if (!s->ws_scenario_enabled) {
                        return 1;
                    }
                    {
                        size_t header_end = 0;
                        int headers_done = _http_headers_complete(s->resp, s->resp_len, &header_end);
                        if (!headers_done) {
                            if (s->resp_len + 1 >= sizeof(s->resp)) {
                                return -1;
                            }
                            return 0;
                        }
                        if (s->resp_len > header_end) {
                            size_t leftover = s->resp_len - header_end;
                            if (leftover > sizeof(s->ws_recv)) {
                                return -1;
                            }
                            memcpy(s->ws_recv, s->resp + header_end, leftover);
                            s->ws_recv_len = leftover;
                        }
                    }
                    s->resp_len = 0;
                    s->state = SESSION_WEBSOCKET_SCENARIO;
                    continue;
                }

                if (s->resp_len + 1 >= sizeof(s->resp)) {
                    return -1;
                }
                return 0;
            }
            if (n == 0) {
                status = _parse_http_status(s->resp, s->resp_len);
                if (status > 0) {
                    if (!websocket_mode) {
                        return 1;
                    }
                    if (status == 101 && !s->ws_scenario_enabled) {
                        return 1;
                    }
                }
                return -1;
            }
            if (!s->use_tls) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return 0;
                }
            }
            return -1;
        }

        if (s->state == SESSION_WEBSOCKET_SCENARIO) {
            int ws_rc = _session_websocket_scenario_progress(s, events, ws_cfg);
            if (ws_rc == 0) {
                return 0;
            }
            return ws_rc > 0 ? 1 : -1;
        }

        return -1;
    }
}

typedef struct {
    long sent;
    long errors;
    long peak_active;
    int fatal_loop_error;
} PassResult;

static int _run_single_pass(
    long attempt_count,
    long concurrency,
    const struct sockaddr_in *addr,
    long long timeout_ns,
    const char *target_ip,
    int target_port,
    const char *path,
    const char *http_method,
    int websocket_mode,
    const TlsConfig *tls_cfg,
    const WsScenarioConfig *ws_cfg,
    long long *latency_samples,
    long latency_sample_cap,
    long *latency_sample_count,
    PassResult *out
) {
    int epfd = -1;
    Session *sessions = NULL;
    struct epoll_event *events = NULL;
    int event_cap = 1;
    long launched = 0;
    long completed = 0;
    long active = 0;
    long peak_active = 0;
    long sent = 0;
    long errors = 0;
    int fatal_loop_error = 0;

    if (out == NULL || addr == NULL || attempt_count < 0 || concurrency <= 0) {
        return -1;
    }

    sessions = (Session *)calloc((size_t)concurrency, sizeof(Session));
    if (sessions == NULL) {
        return -1;
    }
    for (long i = 0; i < concurrency; i++) {
        sessions[i].fd = -1;
    }

    event_cap = (int)(concurrency < 128 ? concurrency : 128);
    if (event_cap < 1) {
        event_cap = 1;
    }
    events = (struct epoll_event *)calloc((size_t)event_cap, sizeof(struct epoll_event));
    if (events == NULL) {
        free(sessions);
        return -1;
    }

    epfd = epoll_create1(0);
    if (epfd < 0) {
        free(events);
        free(sessions);
        out->sent = 0;
        out->errors = attempt_count;
        out->peak_active = 0;
        out->fatal_loop_error = 1;
        return 0;
    }

    while (completed < attempt_count) {
        long long now_ns = monotonic_ns_now();

        for (long i = 0; i < concurrency && launched < attempt_count && active < concurrency; i++) {
            Session *slot = &sessions[i];
            if (slot->in_use) {
                continue;
            }

            launched += 1;
            if (_session_start(
                    slot,
                    epfd,
                    addr,
                    now_ns,
                    timeout_ns,
                    target_ip,
                    target_port,
                    path,
                    http_method,
                    websocket_mode,
                    tls_cfg,
                    ws_cfg
                ) < 0) {
                errors += 1;
                completed += 1;
                continue;
            }

            active += 1;
            if (active > peak_active) {
                peak_active = active;
            }
        }

        if (active <= 0 && launched >= attempt_count) {
            break;
        }

        if (active > 0) {
            int n = epoll_wait(epfd, events, event_cap, 50);
            if (n < 0) {
                if (errno != EINTR) {
                    fatal_loop_error = 1;
                    break;
                }
            } else {
                for (int j = 0; j < n; j++) {
                    Session *s = (Session *)events[j].data.ptr;
                    int outcome;
                    long long fin_ns;

                    if (s == NULL || !s->in_use) {
                        continue;
                    }

                    outcome = _session_progress(s, events[j].events, websocket_mode, tls_cfg, ws_cfg);
                    if (outcome == 0) {
                        continue;
                    }

                    fin_ns = monotonic_ns_now();
                    if (outcome > 0) {
                        sent += 1;
                        if (latency_samples != NULL &&
                            latency_sample_count != NULL &&
                            *latency_sample_count < latency_sample_cap) {
                            latency_samples[*latency_sample_count] = fin_ns - s->start_ns;
                            *latency_sample_count += 1;
                        }
                    } else {
                        errors += 1;
                    }
                    completed += 1;
                    active -= 1;
                    _session_release(epfd, s);
                }
            }
        }

        now_ns = monotonic_ns_now();
        for (long i2 = 0; i2 < concurrency; i2++) {
            Session *s = &sessions[i2];
            if (!s->in_use) {
                continue;
            }
            if (now_ns > s->deadline_ns) {
                errors += 1;
                completed += 1;
                active -= 1;
                _session_release(epfd, s);
            }
        }
    }

    if (fatal_loop_error) {
        for (long i = 0; i < concurrency; i++) {
            if (sessions[i].in_use) {
                errors += 1;
                completed += 1;
                active -= 1;
                _session_release(epfd, &sessions[i]);
            }
        }
    }

    if (completed < attempt_count) {
        errors += (attempt_count - completed);
    }

    close(epfd);
    free(events);
    free(sessions);

    out->sent = sent;
    out->errors = errors < 0 ? 0 : errors;
    out->peak_active = peak_active;
    out->fatal_loop_error = fatal_loop_error;
    return 0;
}

static void _record_handle_run(
    L7Handle *h,
    long attempted,
    long sent,
    long errors,
    long active_peak,
    double conn_rate,
    double handshake_p99_ms,
    long retry_attempts,
    long retry_successes
) {
    if (h == NULL || h->closed) {
        return;
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

    h->runs_total += 1;
    h->sessions_total += attempted;
    h->sessions_ok += sent;
    h->sessions_err += errors;
    h->last_attempted = attempted;
    h->last_sent = sent;
    h->last_errors = errors;
    h->last_retry_attempts = retry_attempts;
    h->last_retry_successes = retry_successes;
    h->last_active_sessions_peak = active_peak;
    h->last_conn_rate = conn_rate;
    h->last_handshake_p99_ms = handshake_p99_ms;
}

static PyObject *_attach_handle_stats(PyObject *result, L7Handle *h) {
    long attempted;
    long sent;
    long errors;
    long peak;
    long retry_attempts;
    long retry_successes;
    double conn_rate;
    double handshake_p99_ms;

    if (result == NULL || h == NULL || !PyDict_Check(result)) {
        return result;
    }

    attempted = _dict_long(result, "attempted", 0);
    sent = _dict_long(result, "sent", 0);
    errors = _dict_long(result, "errors", attempted - sent);
    peak = _dict_long(result, "l7_active_sessions_peak", 0);
    retry_attempts = _dict_long(result, "retry_attempts", 0);
    retry_successes = _dict_long(result, "retry_successes", 0);
    conn_rate = _dict_double(result, "l7_conn_rate", 0.0);
    handshake_p99_ms = _dict_double(result, "l7_handshake_p99_ms", 0.0);

    _record_handle_run(
        h,
        attempted,
        sent,
        errors,
        peak,
        conn_rate,
        handshake_p99_ms,
        retry_attempts,
        retry_successes
    );

    return result;
}

static PyObject *_make_result(
    long attempted,
    long sent,
    long errors,
    long conc_peak,
    double conn_rate,
    double handshake_p99_ms,
    const char *sender_path,
    const char *reason,
    long retry_attempts,
    long retry_successes
) {
    PyObject *out = PyDict_New();
    double session_success_rate = 0.0;
    double step_fail_ratio = 0.0;
    double retry_success_rate = 1.0;

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

    if (attempted > 0) {
        session_success_rate = (double)sent / (double)attempted;
        step_fail_ratio = (double)errors / (double)attempted;
    }
    if (retry_attempts > 0) {
        retry_success_rate = (double)retry_successes / (double)retry_attempts;
    }

    if (_set_long(out, "attempted", attempted) < 0 ||
        _set_long(out, "sent", sent) < 0 ||
        _set_long(out, "errors", errors) < 0 ||
        _set_str(out, "sender_path", sender_path != NULL ? sender_path : "C_STATE") < 0 ||
        _set_str(out, "sender_fallback_reason", reason != NULL ? reason : "none") < 0 ||
        _set_long(out, "l7_active_sessions_peak", conc_peak) < 0 ||
        _set_double(out, "l7_conn_rate", conn_rate) < 0 ||
        _set_double(out, "l7_handshake_p99_ms", handshake_p99_ms) < 0 ||
        _set_double(out, "l7_step_fail_ratio", step_fail_ratio) < 0 ||
        _set_double(out, "session_success_rate", session_success_rate) < 0 ||
        _set_double(out, "retry_success_rate", retry_success_rate) < 0 ||
        _set_long(out, "retry_attempts", retry_attempts) < 0 ||
        _set_long(out, "retry_successes", retry_successes) < 0) {
        Py_DECREF(out);
        return NULL;
    }

    return out;
}

static PyObject *_run_state_machine(PyObject *cfg, int websocket_mode, const char *sender_path, L7Handle *handle) {
    long count;
    long session_repeats;
    long total_attempts;
    long concurrency;
    long max_active_sessions;
    long max_retries;
    double timeout_s;
    const char *target_ip;
    long target_port;
    const char *path;
    const char *scheme;
    int verify_tls;
    int use_tls;
    const char *server_name;
    char http_method[24];
    long ws_scenario_enabled;
    long ws_ping_count;
    long ws_subscribe_count;
    const char *ws_auth_message;
    const char *ws_subscribe_messages;
    const char *ws_ping_message;
    int ws_await_response;
    struct sockaddr_in addr;
    long long timeout_ns;
    const long sample_cap_hard = 200000;
    long latency_sample_cap;
    long latency_sample_count = 0;
    long long *latency_samples = NULL;
    long long run_start_ns;
    long long run_end_ns;
    double elapsed_s = 0.0;
    double conn_rate = 0.0;
    double handshake_p99_ms = 0.0;
    long remaining;
    long sent_total = 0;
    long peak_active = 0;
    long retry_attempts = 0;
    long retry_successes = 0;
    int fatal_loop_error = 0;
    const char *final_reason = "none";
    PyObject *result = NULL;
    TlsConfig tls_cfg;
    WsScenarioConfig ws_cfg;
#ifdef SAMURAI_WITH_OPENSSL
    const char *tls_setup_reason = "none";
#endif

    if (!PyDict_Check(cfg)) {
        return _attach_handle_stats(_make_result(0, 0, 0, 0, 0.0, 0.0, sender_path, "invalid_config", 0, 0), handle);
    }

    count = _dict_long(cfg, "count", 0);
    session_repeats = _dict_long(cfg, "session_repeats", 1);
    if (session_repeats < 1) {
        session_repeats = 1;
    }
    if (count <= 0) {
        return _attach_handle_stats(_make_result(0, 0, 0, 0, 0.0, 0.0, sender_path, "none", 0, 0), handle);
    }
    if (count > LONG_MAX / session_repeats) {
        return _attach_handle_stats(
            _make_result(count, 0, count, 0, 0.0, 0.0, sender_path, "count_overflow", 0, 0),
            handle
        );
    }
    total_attempts = count * session_repeats;

    concurrency = _dict_long(cfg, "concurrency", 1);
    max_active_sessions = _dict_long(cfg, "max_active_sessions", 0);
    max_retries = _dict_long(cfg, "retries", 0);
    timeout_s = _dict_double(cfg, "timeout_s", websocket_mode ? 3.0 : 5.0);
    target_ip = _dict_cstr(cfg, "target_ip", "");
    target_port = _dict_long(cfg, "target_port", websocket_mode ? 80 : 80);
    path = _dict_cstr(cfg, websocket_mode ? "ws_path" : "http_path", "/");
    scheme = _dict_cstr(cfg, "scheme", websocket_mode ? "ws" : "http");
    verify_tls = _dict_bool(cfg, "verify", 0);
    use_tls = _scheme_is_tls(scheme) || verify_tls;
    server_name = _dict_cstr(cfg, "server_name", target_ip);
    _copy_upper_ascii(http_method, sizeof(http_method), _dict_cstr(cfg, "http_method", "GET"), "GET");

    memset(&tls_cfg, 0, sizeof(tls_cfg));
    tls_cfg.enabled = use_tls ? 1 : 0;
    tls_cfg.verify_peer = verify_tls ? 1 : 0;
    tls_cfg.server_name = server_name;
    memset(&ws_cfg, 0, sizeof(ws_cfg));

    if (max_retries < 0) {
        max_retries = 0;
    }
    if (max_retries > 8) {
        max_retries = 8;
    }
    if (concurrency < 1) {
        concurrency = 1;
    }
    if (max_active_sessions > 0 && concurrency > max_active_sessions) {
        concurrency = max_active_sessions;
    }
    if (concurrency > total_attempts) {
        concurrency = total_attempts;
    }
    if (concurrency < 1) {
        concurrency = 1;
    }
    if (timeout_s <= 0.0) {
        timeout_s = websocket_mode ? 3.0 : 5.0;
    }

    if (tls_cfg.enabled) {
#ifdef SAMURAI_WITH_OPENSSL
        tls_cfg.ctx = _tls_ctx_create(tls_cfg.verify_peer, &tls_setup_reason);
        if (tls_cfg.ctx == NULL) {
            return _attach_handle_stats(
                _make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, sender_path, tls_setup_reason, 0, 0),
                handle
            );
        }
#else
        return _attach_handle_stats(
            _make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, sender_path, "tls_not_supported", 0, 0),
            handle
        );
#endif
    }

    if (websocket_mode) {
        ws_scenario_enabled = _dict_bool(cfg, "ws_scenario_enabled", 0);
        ws_ping_count = _dict_long(cfg, "ws_ping_count", 1);
        ws_subscribe_count = _dict_long(cfg, "ws_subscribe_count", 0);
        ws_auth_message = _dict_cstr(cfg, "ws_auth_message", "");
        ws_subscribe_messages = _dict_cstr(cfg, "ws_subscribe_messages", "");
        ws_ping_message = _dict_cstr(cfg, "ws_ping_message", "ping");
        ws_await_response = _dict_bool(cfg, "ws_await_response", 0);
        if (ws_ping_count < 0) {
            ws_ping_count = 0;
        }
        if (ws_ping_count > 512) {
            ws_ping_count = 512;
        }
        if (ws_subscribe_count < 0) {
            ws_subscribe_count = 0;
        }
        if (ws_subscribe_count > WS_MAX_SUBSCRIBE_MESSAGES) {
            ws_subscribe_count = WS_MAX_SUBSCRIBE_MESSAGES;
        }

        _copy_bounded_cstr(ws_cfg.auth_message, sizeof(ws_cfg.auth_message), ws_auth_message, "");
        _copy_bounded_cstr(ws_cfg.ping_message, sizeof(ws_cfg.ping_message), ws_ping_message, "ping");
        ws_cfg.await_response = ws_await_response ? 1 : 0;
        ws_cfg.ping_count = (int)ws_ping_count;
        ws_cfg.subscribe_count = _ws_parse_subscribe_messages(&ws_cfg, ws_subscribe_messages, ws_subscribe_count);
        ws_cfg.enabled = ws_scenario_enabled ? 1 : 0;
        if (!ws_cfg.enabled &&
            (ws_cfg.await_response || ws_cfg.ping_count != 1 || ws_cfg.subscribe_count > 0 || ws_cfg.auth_message[0] != '\0')) {
            ws_cfg.enabled = 1;
        }
        ws_cfg.total_steps =
            (ws_cfg.auth_message[0] != '\0' ? 1 : 0) +
            ws_cfg.subscribe_count +
            ws_cfg.ping_count;
        if (ws_cfg.total_steps < 0) {
            ws_cfg.total_steps = 0;
        }
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)target_port);
    if (target_ip[0] == '\0') {
        return _attach_handle_stats(
            _make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, sender_path, "target_ip_missing", 0, 0),
            handle
        );
    }
    if (target_port <= 0 || target_port > 65535) {
        return _attach_handle_stats(
            _make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, sender_path, "target_port_invalid", 0, 0),
            handle
        );
    }
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) != 1) {
        return _attach_handle_stats(
            _make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, sender_path, "target_ip_invalid", 0, 0),
            handle
        );
    }

    timeout_ns = (long long)(timeout_s * 1000000000.0);
    if (timeout_ns < 1000000LL) {
        timeout_ns = 1000000LL;
    }

    latency_sample_cap = total_attempts < sample_cap_hard ? total_attempts : sample_cap_hard;
    if (latency_sample_cap > 0) {
        latency_samples = (long long *)PyMem_Calloc((size_t)latency_sample_cap, sizeof(long long));
        if (latency_samples == NULL) {
            return PyErr_NoMemory();
        }
    }

    run_start_ns = monotonic_ns_now();
    remaining = total_attempts;

    for (long pass_idx = 0; remaining > 0 && pass_idx <= max_retries; pass_idx++) {
        PassResult pass;
        long current = remaining;
        int pass_rc = 0;

        pass.sent = 0;
        pass.errors = current;
        pass.peak_active = 0;
        pass.fatal_loop_error = 0;

        if (pass_idx > 0) {
            retry_attempts += current;
        }

        Py_BEGIN_ALLOW_THREADS
        pass_rc = _run_single_pass(
            current,
            concurrency,
            &addr,
            timeout_ns,
            target_ip,
            (int)target_port,
            path,
            http_method,
            websocket_mode,
            &tls_cfg,
            websocket_mode ? &ws_cfg : NULL,
            latency_samples,
            latency_sample_cap,
            &latency_sample_count,
            &pass
        );
        Py_END_ALLOW_THREADS

        if (pass_rc < 0) {
#ifdef SAMURAI_WITH_OPENSSL
            if (tls_cfg.ctx != NULL) {
                SSL_CTX_free(tls_cfg.ctx);
                tls_cfg.ctx = NULL;
            }
#endif
            PyMem_Free(latency_samples);
            if (!PyErr_Occurred()) {
                PyErr_SetString(PyExc_RuntimeError, "l7 state machine pass failed");
            }
            return NULL;
        }

        if (pass.sent < 0) {
            pass.sent = 0;
        }
        if (pass.sent > current) {
            pass.sent = current;
        }
        if (pass.errors < 0) {
            pass.errors = current - pass.sent;
        }
        if (pass.errors < 0) {
            pass.errors = 0;
        }

        sent_total += pass.sent;
        if (pass_idx > 0) {
            retry_successes += pass.sent;
        }
        if (pass.peak_active > peak_active) {
            peak_active = pass.peak_active;
        }

        remaining = pass.errors;
        if (pass.fatal_loop_error) {
            fatal_loop_error = 1;
            break;
        }
    }

    if (sent_total > total_attempts) {
        sent_total = total_attempts;
    }

    run_end_ns = monotonic_ns_now();
    if (run_end_ns > run_start_ns) {
        elapsed_s = (double)(run_end_ns - run_start_ns) / 1e9;
    }
    if (elapsed_s > 0.0) {
        conn_rate = (double)sent_total / elapsed_s;
    }

    if (latency_sample_count > 0 && latency_samples != NULL) {
        long p99_index;
        qsort(latency_samples, (size_t)latency_sample_count, sizeof(long long), _cmp_longlong);
        p99_index = (long)(0.99 * (double)(latency_sample_count - 1));
        if (p99_index < 0) {
            p99_index = 0;
        }
        if (p99_index >= latency_sample_count) {
            p99_index = latency_sample_count - 1;
        }
        handshake_p99_ms = (double)latency_samples[p99_index] / 1e6;
    }

    if (fatal_loop_error) {
        final_reason = "epoll_loop_failed";
    } else if (remaining > 0 && max_retries > 0) {
        final_reason = "retries_exhausted";
    }

    result = _make_result(
        total_attempts,
        sent_total,
        total_attempts - sent_total,
        peak_active,
        conn_rate,
        handshake_p99_ms,
        sender_path,
        final_reason,
        retry_attempts,
        retry_successes
    );
    if (result != NULL) {
        if (_set_long(result, "session_repeats", session_repeats) < 0 ||
            _set_long(result, "max_retries", max_retries) < 0 ||
            _set_str(result, "scheme", scheme) < 0) {
            Py_DECREF(result);
            result = NULL;
        } else if (websocket_mode) {
            if (_set_long(result, "ws_scenario_enabled", ws_cfg.enabled ? 1 : 0) < 0 ||
                _set_long(result, "ws_step_count", ws_cfg.total_steps) < 0 ||
                _set_long(result, "ws_subscribe_count", ws_cfg.subscribe_count) < 0 ||
                _set_long(result, "ws_ping_count", ws_cfg.ping_count) < 0 ||
                _set_long(result, "ws_await_response", ws_cfg.await_response ? 1 : 0) < 0) {
                Py_DECREF(result);
                result = NULL;
            }
        }
    }

    PyMem_Free(latency_samples);
#ifdef SAMURAI_WITH_OPENSSL
    if (tls_cfg.ctx != NULL) {
        SSL_CTX_free(tls_cfg.ctx);
        tls_cfg.ctx = NULL;
    }
#endif
    return _attach_handle_stats(result, handle);
}

static void _capsule_destructor(PyObject *capsule) {
    L7Handle *h = (L7Handle *)PyCapsule_GetPointer(capsule, "samurai.l7_state.handle");
    if (h != NULL) {
        PyMem_Free(h);
    } else {
        PyErr_Clear();
    }
}

static L7Handle *_get_handle(PyObject *obj) {
    return (L7Handle *)PyCapsule_GetPointer(obj, "samurai.l7_state.handle");
}

static PyObject *l7_open(PyObject *self, PyObject *args) {
    PyObject *cfg = NULL;
    L7Handle *h = NULL;

    (void)self;

    if (!PyArg_ParseTuple(args, "O", &cfg)) {
        return NULL;
    }

    h = (L7Handle *)PyMem_Calloc(1, sizeof(L7Handle));
    if (h == NULL) {
        return PyErr_NoMemory();
    }

    h->id = g_l7_next_id++;
    (void)cfg;
    return PyCapsule_New((void *)h, "samurai.l7_state.handle", _capsule_destructor);
}

static PyObject *l7_close(PyObject *self, PyObject *args) {
    PyObject *handle_obj = NULL;
    L7Handle *h = NULL;

    (void)self;

    if (!PyArg_ParseTuple(args, "O", &handle_obj)) {
        return NULL;
    }

    h = _get_handle(handle_obj);
    if (h == NULL) {
        return NULL;
    }

    h->closed = 1;
    Py_RETURN_NONE;
}

static PyObject *l7_snapshot(PyObject *self, PyObject *args) {
    PyObject *handle_obj = NULL;
    L7Handle *h = NULL;
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
        _set_long(out, "runs_total", h->runs_total) < 0 ||
        _set_long(out, "sessions_total", h->sessions_total) < 0 ||
        _set_long(out, "sessions_ok", h->sessions_ok) < 0 ||
        _set_long(out, "sessions_err", h->sessions_err) < 0 ||
        _set_long(out, "last_attempted", h->last_attempted) < 0 ||
        _set_long(out, "last_sent", h->last_sent) < 0 ||
        _set_long(out, "last_errors", h->last_errors) < 0 ||
        _set_long(out, "last_retry_attempts", h->last_retry_attempts) < 0 ||
        _set_long(out, "last_retry_successes", h->last_retry_successes) < 0 ||
        _set_long(out, "last_active_sessions_peak", h->last_active_sessions_peak) < 0 ||
        _set_double(out, "last_conn_rate", h->last_conn_rate) < 0 ||
        _set_double(out, "last_handshake_p99_ms", h->last_handshake_p99_ms) < 0 ||
        _set_long(out, "closed", h->closed ? 1 : 0) < 0) {
        Py_DECREF(out);
        return NULL;
    }

    return out;
}

static PyObject *l7_tls_supported(PyObject *self, PyObject *args) {
    (void)self;
    (void)args;
#ifdef SAMURAI_WITH_OPENSSL
    Py_RETURN_TRUE;
#else
    Py_RETURN_FALSE;
#endif
}

static PyObject *l7_h2_supported(PyObject *self, PyObject *args) {
    (void)self;
    (void)args;
#ifdef SAMURAI_WITH_NGHTTP2
    Py_RETURN_TRUE;
#else
    Py_RETURN_FALSE;
#endif
}

static PyObject *l7_quic_supported(PyObject *self, PyObject *args) {
    (void)self;
    (void)args;
#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_NGHTTP3)
    if (_quic_stack_probe(NULL)) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
#else
    Py_RETURN_FALSE;
#endif
}

static PyObject *l7_run_http1_stateful(PyObject *self, PyObject *args) {
    PyObject *cfg = NULL;
    PyObject *handle_obj = NULL;
    L7Handle *h = NULL;

    (void)self;

    if (PyArg_ParseTuple(args, "OO", &handle_obj, &cfg)) {
        h = _get_handle(handle_obj);
        if (h == NULL) {
            return NULL;
        }
        if (h->closed) {
            PyErr_SetString(PyExc_RuntimeError, "l7 handle is closed");
            return NULL;
        }
    } else {
        PyErr_Clear();
        if (!PyArg_ParseTuple(args, "O", &cfg)) {
            return NULL;
        }
    }

    return _run_state_machine(cfg, 0, "C_STATE_HTTP1", h);
}

static PyObject *l7_run_websocket_stateful(PyObject *self, PyObject *args) {
    PyObject *cfg = NULL;
    PyObject *handle_obj = NULL;
    L7Handle *h = NULL;

    (void)self;

    if (PyArg_ParseTuple(args, "OO", &handle_obj, &cfg)) {
        h = _get_handle(handle_obj);
        if (h == NULL) {
            return NULL;
        }
        if (h->closed) {
            PyErr_SetString(PyExc_RuntimeError, "l7 handle is closed");
            return NULL;
        }
    } else {
        PyErr_Clear();
        if (!PyArg_ParseTuple(args, "O", &cfg)) {
            return NULL;
        }
    }

    return _run_state_machine(cfg, 1, "C_STATE_WS", h);
}

#ifdef SAMURAI_WITH_NGHTTP2
static int _set_blocking_mode(int fd, int blocking) {
    int flags;
    if (fd < 0) {
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    if (fcntl(fd, F_SETFL, flags) < 0) {
        return -1;
    }
    return 0;
}

static int _set_socket_io_timeout(int fd, long timeout_ms) {
    struct timeval tv;
    if (timeout_ms < 1) {
        timeout_ms = 1;
    }
    tv.tv_sec = (time_t)(timeout_ms / 1000);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return -1;
    }
    return 0;
}

static int _connect_with_timeout(int fd, const struct sockaddr_in *addr, long timeout_ms) {
    int rc;
    int sock_err = 0;
    socklen_t sock_err_len = sizeof(sock_err);
    fd_set wfds;
    struct timeval tv;

    if (fd < 0 || addr == NULL) {
        return -1;
    }
    if (_set_blocking_mode(fd, 0) < 0) {
        return -1;
    }

    rc = connect(fd, (const struct sockaddr *)addr, sizeof(*addr));
    if (rc == 0) {
        return 0;
    }
    if (errno != EINPROGRESS) {
        return -1;
    }

    if (timeout_ms < 1) {
        timeout_ms = 1;
    }

    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    tv.tv_sec = (time_t)(timeout_ms / 1000);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000);
    for (;;) {
        rc = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (rc <= 0) {
        if (rc == 0) {
            errno = ETIMEDOUT;
        }
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_err_len) < 0) {
        return -1;
    }
    if (sock_err != 0) {
        errno = sock_err;
        return -1;
    }
    return 0;
}

typedef struct {
    int fd;
    int use_tls;
#ifdef SAMURAI_WITH_OPENSSL
    SSL *ssl;
#endif
    long submitted;
    long completed;
    long failed;
    long rst_stream;
    long goaway;
    int transport_error;
    int protocol_error;
} H2ConnContext;

typedef struct {
    long sent;
    long errors;
    long submitted_count;
    long goaway_count;
    long rst_stream_count;
    int transport_error;
    int protocol_error;
    long long handshake_ns;
} H2ConnResult;

static ssize_t _h2_send_callback(
    nghttp2_session *session,
    const uint8_t *data,
    size_t length,
    int flags,
    void *user_data
) {
    H2ConnContext *ctx = (H2ConnContext *)user_data;
    size_t off = 0;
    (void)session;
    (void)flags;
    if (ctx == NULL) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    while (off < length) {
        ssize_t wr = -1;
        if (ctx->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
            int tls_wr;
            if (ctx->ssl == NULL) {
                ctx->transport_error = 1;
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            tls_wr = SSL_write(ctx->ssl, data + off, (int)(length - off));
            if (tls_wr > 0) {
                wr = (ssize_t)tls_wr;
            } else {
                int err = SSL_get_error(ctx->ssl, tls_wr);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    errno = EAGAIN;
                    continue;
                }
                ctx->transport_error = 1;
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
#else
            ctx->transport_error = 1;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
#endif
        } else {
            wr = send(ctx->fd, data + off, length - off, MSG_NOSIGNAL);
        }
        if (wr > 0) {
            off += (size_t)wr;
            continue;
        }
        if (wr < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        ctx->transport_error = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return (ssize_t)length;
}

static int _h2_on_frame_recv_callback(
    nghttp2_session *session,
    const nghttp2_frame *frame,
    void *user_data
) {
    H2ConnContext *ctx = (H2ConnContext *)user_data;
    (void)session;
    if (ctx != NULL && frame != NULL && frame->hd.type == NGHTTP2_GOAWAY) {
        ctx->goaway += 1;
    }
    return 0;
}

static int _h2_on_stream_close_callback(
    nghttp2_session *session,
    int32_t stream_id,
    uint32_t error_code,
    void *user_data
) {
    H2ConnContext *ctx = (H2ConnContext *)user_data;
    (void)session;
    if (ctx == NULL || stream_id <= 0) {
        return 0;
    }
    if (error_code == NGHTTP2_NO_ERROR) {
        ctx->completed += 1;
    } else {
        ctx->failed += 1;
        ctx->rst_stream += 1;
    }
    return 0;
}

static ssize_t _h2_socket_read(H2ConnContext *ctx, unsigned char *buf, size_t cap) {
    if (ctx == NULL || buf == NULL || cap == 0) {
        errno = EINVAL;
        return -1;
    }
    if (ctx->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
        int rd;
        if (ctx->ssl == NULL) {
            errno = EIO;
            return -1;
        }
        rd = SSL_read(ctx->ssl, buf, (int)cap);
        if (rd > 0) {
            return (ssize_t)rd;
        }
        if (rd == 0) {
            return 0;
        }
        {
            int err = SSL_get_error(ctx->ssl, rd);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                errno = EAGAIN;
            } else if (err == SSL_ERROR_ZERO_RETURN) {
                return 0;
            } else {
                errno = EIO;
            }
        }
        return -1;
#else
        errno = EIO;
        return -1;
#endif
    }
    return recv(ctx->fd, buf, cap, 0);
}

static void _h2_run_connection(
    const struct sockaddr_in *addr,
    const char *target_ip,
    int target_port,
    const char *scheme,
    const char *method,
    const char *path,
    const char *user_agent,
    char **plan_methods,
    char **plan_paths,
    char **plan_user_agents,
    long plan_offset,
    long request_count,
    long timeout_ms,
    int use_tls,
#ifdef SAMURAI_WITH_OPENSSL
    SSL_CTX *tls_ctx,
#endif
    const char *server_name,
    H2ConnResult *out
) {
    int fd = -1;
    long long hs_start_ns = 0;
    long long hs_end_ns = 0;
    H2ConnContext ctx;
    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_session *session = NULL;
    unsigned char read_buf[16384];
    char authority[160];
    long long deadline_ns = 0;

    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (request_count <= 0 || addr == NULL || target_ip == NULL) {
        return;
    }
    out->errors = request_count;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        out->transport_error = 1;
        return;
    }
    hs_start_ns = monotonic_ns_now();
    if (_connect_with_timeout(fd, addr, timeout_ms) < 0) {
        out->transport_error = 1;
        goto done;
    }
    if (_set_blocking_mode(fd, 1) < 0) {
        out->transport_error = 1;
        goto done;
    }
    if (_set_socket_io_timeout(fd, timeout_ms) < 0) {
        out->transport_error = 1;
        goto done;
    }

    ctx.fd = fd;
    ctx.use_tls = use_tls ? 1 : 0;
#ifdef SAMURAI_WITH_OPENSSL
    ctx.ssl = NULL;
#endif

    if (ctx.use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
        const unsigned char *alpn = NULL;
        unsigned int alpn_len = 0;
        if (tls_ctx == NULL) {
            out->transport_error = 1;
            goto done;
        }
        ctx.ssl = SSL_new(tls_ctx);
        if (ctx.ssl == NULL) {
            out->transport_error = 1;
            goto done;
        }
        if (SSL_set_fd(ctx.ssl, fd) != 1) {
            out->transport_error = 1;
            goto done;
        }
        if (server_name != NULL && server_name[0] != '\0' && !_is_ipv4_literal(server_name)) {
            (void)SSL_set_tlsext_host_name(ctx.ssl, server_name);
        }
        if (SSL_connect(ctx.ssl) != 1) {
            out->transport_error = 1;
            goto done;
        }
        SSL_get0_alpn_selected(ctx.ssl, &alpn, &alpn_len);
        if (alpn_len != 2 || alpn == NULL || memcmp(alpn, "h2", 2) != 0) {
            out->protocol_error = 1;
            goto done;
        }
#else
        out->transport_error = 1;
        goto done;
#endif
    }

    hs_end_ns = monotonic_ns_now();
    if (hs_end_ns > hs_start_ns) {
        out->handshake_ns = hs_end_ns - hs_start_ns;
    }

    if (nghttp2_session_callbacks_new(&callbacks) != 0 || callbacks == NULL) {
        out->protocol_error = 1;
        goto done;
    }
    nghttp2_session_callbacks_set_send_callback(callbacks, _h2_send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, _h2_on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, _h2_on_stream_close_callback);
    if (nghttp2_session_client_new(&session, callbacks, &ctx) != 0 || session == NULL) {
        out->protocol_error = 1;
        goto done;
    }
    if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, NULL, 0) != 0) {
        ctx.protocol_error = 1;
        goto finalize_session;
    }

    if (snprintf(authority, sizeof(authority), "%s:%d", target_ip, target_port) < 0) {
        ctx.protocol_error = 1;
        goto finalize_session;
    }

    for (long idx = 0; idx < request_count; idx++) {
        long plan_idx = plan_offset + idx;
        const char *req_method = (method != NULL && method[0] != '\0') ? method : "GET";
        const char *req_path = (path != NULL && path[0] != '\0') ? path : "/";
        const char *req_scheme = (scheme != NULL && scheme[0] != '\0') ? scheme : (ctx.use_tls ? "https" : "http");
        const char *req_ua = (user_agent != NULL && user_agent[0] != '\0') ? user_agent : NULL;
        nghttp2_nv hdrs[5];
        size_t hdr_count = 4;

        if (plan_idx >= 0) {
            if (plan_methods != NULL && plan_methods[plan_idx] != NULL && plan_methods[plan_idx][0] != '\0') {
                req_method = plan_methods[plan_idx];
            }
            if (plan_paths != NULL && plan_paths[plan_idx] != NULL && plan_paths[plan_idx][0] != '\0') {
                req_path = plan_paths[plan_idx];
            }
            if ((req_ua == NULL || req_ua[0] == '\0') &&
                plan_user_agents != NULL &&
                plan_user_agents[plan_idx] != NULL &&
                plan_user_agents[plan_idx][0] != '\0') {
                req_ua = plan_user_agents[plan_idx];
            }
        }

        hdrs[0].name = (uint8_t *)":method";
        hdrs[0].value = (uint8_t *)req_method;
        hdrs[0].namelen = strlen(":method");
        hdrs[0].valuelen = strlen(req_method);
        hdrs[0].flags = NGHTTP2_NV_FLAG_NONE;
        hdrs[1].name = (uint8_t *)":scheme";
        hdrs[1].value = (uint8_t *)req_scheme;
        hdrs[1].namelen = strlen(":scheme");
        hdrs[1].valuelen = strlen(req_scheme);
        hdrs[1].flags = NGHTTP2_NV_FLAG_NONE;
        hdrs[2].name = (uint8_t *)":authority";
        hdrs[2].value = (uint8_t *)authority;
        hdrs[2].namelen = strlen(":authority");
        hdrs[2].valuelen = strlen(authority);
        hdrs[2].flags = NGHTTP2_NV_FLAG_NONE;
        hdrs[3].name = (uint8_t *)":path";
        hdrs[3].value = (uint8_t *)req_path;
        hdrs[3].namelen = strlen(":path");
        hdrs[3].valuelen = strlen(req_path);
        hdrs[3].flags = NGHTTP2_NV_FLAG_NONE;
        if (req_ua != NULL && req_ua[0] != '\0') {
            hdrs[4].name = (uint8_t *)"user-agent";
            hdrs[4].value = (uint8_t *)req_ua;
            hdrs[4].namelen = strlen("user-agent");
            hdrs[4].valuelen = strlen(req_ua);
            hdrs[4].flags = NGHTTP2_NV_FLAG_NONE;
            hdr_count = 5;
        }
        if (nghttp2_submit_request(session, NULL, hdrs, hdr_count, NULL, NULL) < 0) {
            ctx.protocol_error = 1;
            break;
        }
        ctx.submitted += 1;
    }

    if (nghttp2_session_send(session) < 0) {
        if (!ctx.transport_error) {
            ctx.protocol_error = 1;
        } else if (ctx.submitted > 0 && ctx.completed == 0 && ctx.failed == 0) {
            /* Early disconnect right after request submission is a protocol break for H2 flow. */
            ctx.protocol_error = 1;
        }
        goto finalize_session;
    }

    deadline_ns = monotonic_ns_now() + ((long long)timeout_ms * 1000000LL);
    while (ctx.completed + ctx.failed < ctx.submitted) {
        ssize_t rd;
        int recv_rc;
        if (monotonic_ns_now() > deadline_ns) {
            ctx.transport_error = 1;
            break;
        }
        rd = _h2_socket_read(&ctx, read_buf, sizeof(read_buf));
        if (rd > 0) {
            recv_rc = nghttp2_session_mem_recv(session, read_buf, (size_t)rd);
            if (recv_rc < 0) {
                ctx.protocol_error = 1;
                break;
            }
            if (nghttp2_session_send(session) < 0) {
                if (!ctx.transport_error) {
                    ctx.protocol_error = 1;
                } else if (ctx.completed + ctx.failed < ctx.submitted) {
                    ctx.protocol_error = 1;
                }
                break;
            }
            continue;
        }
        if (rd == 0) {
            /* Peer closed before all submitted streams completed: classify as protocol break. */
            if (ctx.completed + ctx.failed < ctx.submitted && !ctx.transport_error) {
                ctx.protocol_error = 1;
            }
            break;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
        ctx.transport_error = 1;
        break;
    }

    if (ctx.submitted < request_count) {
        ctx.failed += (request_count - ctx.submitted);
        if (!ctx.protocol_error) {
            ctx.protocol_error = 1;
        }
    }
    if (ctx.completed + ctx.failed < request_count) {
        ctx.failed += (request_count - (ctx.completed + ctx.failed));
        if (!ctx.protocol_error) {
            ctx.transport_error = 1;
        }
    }

finalize_session:
    out->submitted_count = ctx.submitted;
    out->sent = ctx.completed;
    if (out->sent < 0) {
        out->sent = 0;
    }
    if (out->sent > request_count) {
        out->sent = request_count;
    }
    out->errors = request_count - out->sent;
    out->goaway_count = ctx.goaway;
    out->rst_stream_count = ctx.rst_stream;
    out->transport_error = ctx.transport_error;
    out->protocol_error = ctx.protocol_error;
    if (out->errors > 0 && !out->transport_error && !out->protocol_error) {
        out->transport_error = 1;
    }

done:
    if (session != NULL) {
        nghttp2_session_del(session);
    }
    if (callbacks != NULL) {
        nghttp2_session_callbacks_del(callbacks);
    }
#ifdef SAMURAI_WITH_OPENSSL
    if (ctx.ssl != NULL) {
        SSL_shutdown(ctx.ssl);
        SSL_free(ctx.ssl);
        ctx.ssl = NULL;
    }
#endif
    if (fd >= 0) {
        close(fd);
    }
}
#endif

static PyObject *l7_run_http2_stateful(PyObject *self, PyObject *args) {
    PyObject *cfg = NULL;
    PyObject *handle_obj = NULL;
    L7Handle *h = NULL;
    long count = 0;
    long session_repeats = 1;
    long total_attempts = 0;
    long target_port = 0;
    const char *target_ip = "";
    struct sockaddr_in addr;
    PyObject *result = NULL;
#ifdef SAMURAI_WITH_NGHTTP2
    long h2_connections = 1;
    long h2_streams_per_conn = 100;
    double timeout_s = 5.0;
    long timeout_ms = 5000;
    int verify_tls = 0;
    int use_tls = 0;
    const char *scheme = "https";
    const char *path = "/";
    const char *user_agent = "";
    const char *server_name = "";
    char http_method[24];
    char **plan_methods = NULL;
    char **plan_paths = NULL;
    char **plan_user_agents = NULL;
    long plan_methods_used = 0;
    long plan_paths_used = 0;
    long plan_uas_used = 0;
    long plan_items_used = 0;
    long plan_offset = 0;
    long plan_items_cfg = 0;
    long sent_total = 0;
    long errors_total = 0;
    long peak_active = 0;
    long total_goaway = 0;
    long total_rst = 0;
    long total_submitted = 0;
    long connections_used = 0;
    int saw_transport_error = 0;
    int saw_protocol_error = 0;
    long long run_start_ns = 0;
    long long run_end_ns = 0;
    double elapsed_s = 0.0;
    double conn_rate = 0.0;
    double handshake_p99_ms = 0.0;
    const char *final_reason = "none";
    const long sample_cap_hard = 200000;
    long conn_sample_cap = 0;
    long sample_count = 0;
    long long *handshake_samples = NULL;
    long remaining = 0;
#ifdef SAMURAI_WITH_OPENSSL
    SSL_CTX *tls_ctx = NULL;
    const char *tls_reason = "none";
    static const unsigned char alpn_h2[] = {2, 'h', '2'};
#endif
#endif

    (void)self;

    if (PyArg_ParseTuple(args, "OO", &handle_obj, &cfg)) {
        h = _get_handle(handle_obj);
        if (h == NULL) {
            return NULL;
        }
        if (h->closed) {
            PyErr_SetString(PyExc_RuntimeError, "l7 handle is closed");
            return NULL;
        }
    } else {
        PyErr_Clear();
        if (!PyArg_ParseTuple(args, "O", &cfg)) {
            return NULL;
        }
    }

    if (!PyDict_Check(cfg)) {
        return _attach_handle_stats(_make_result(0, 0, 0, 0, 0.0, 0.0, "C_STATE_H2", "invalid_config", 0, 0), h);
    }

    count = _dict_long(cfg, "count", 0);
    session_repeats = _dict_long(cfg, "session_repeats", 1);
    if (session_repeats < 1) {
        session_repeats = 1;
    }
    if (count <= 0) {
        return _attach_handle_stats(_make_result(0, 0, 0, 0, 0.0, 0.0, "C_STATE_H2", "none", 0, 0), h);
    }
    if (count > LONG_MAX / session_repeats) {
        return _attach_handle_stats(_make_result(count, 0, count, 0, 0.0, 0.0, "C_STATE_H2", "count_overflow", 0, 0), h);
    }
    total_attempts = count * session_repeats;

#ifdef SAMURAI_WITH_NGHTTP2
    target_ip = _dict_cstr(cfg, "target_ip", "");
    target_port = _dict_long(cfg, "target_port", 443);
    scheme = _dict_cstr(cfg, "scheme", "https");
    path = _dict_cstr(cfg, "http_path", "/");
    user_agent = _dict_cstr(cfg, "user_agent", "");
    verify_tls = _dict_bool(cfg, "verify", 0);
    use_tls = _scheme_is_tls(scheme) || verify_tls;
    server_name = _dict_cstr(cfg, "server_name", target_ip);
    plan_items_cfg = _dict_long(cfg, "h2_request_plan_count", 0);
    if (plan_items_cfg < 0) {
        plan_items_cfg = 0;
    }
    _copy_upper_ascii(http_method, sizeof(http_method), _dict_cstr(cfg, "http_method", "GET"), "GET");

    timeout_s = _dict_double(cfg, "timeout_s", 5.0);
    if (timeout_s <= 0.0) {
        timeout_s = 5.0;
    }
    timeout_ms = (long)(timeout_s * 1000.0);
    if (timeout_ms < 50) {
        timeout_ms = 50;
    }

    h2_connections = _dict_long(cfg, "h2_connections", _dict_long(cfg, "http2_connections", _dict_long(cfg, "concurrency", 1)));
    h2_streams_per_conn = _dict_long(cfg, "h2_streams_per_conn", _dict_long(cfg, "http2_streams_per_conn", 100));
    if (h2_connections < 1) {
        h2_connections = 1;
    }
    if (h2_streams_per_conn < 1) {
        h2_streams_per_conn = 1;
    }
    if (h2_streams_per_conn > 10000) {
        h2_streams_per_conn = 10000;
    }
    if (h2_connections > total_attempts) {
        h2_connections = total_attempts;
    }
    if (h2_connections < 1) {
        h2_connections = 1;
    }
#else
    target_ip = _dict_cstr(cfg, "target_ip", "");
    target_port = _dict_long(cfg, "target_port", 443);
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (target_ip[0] == '\0') {
        return _attach_handle_stats(_make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, "C_STATE_H2", "target_ip_missing", 0, 0), h);
    }
    if (target_port <= 0 || target_port > 65535) {
        return _attach_handle_stats(_make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, "C_STATE_H2", "target_port_invalid", 0, 0), h);
    }
    addr.sin_port = htons((uint16_t)target_port);
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) != 1) {
        return _attach_handle_stats(_make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, "C_STATE_H2", "target_ip_invalid", 0, 0), h);
    }

#ifndef SAMURAI_WITH_NGHTTP2
    result = _make_result(
        total_attempts,
        0,
        total_attempts,
        0,
        0.0,
        0.0,
        "C_STATE_H2",
        "h2_capability_unavailable",
        0,
        0
    );
    if (result != NULL) {
        if (_set_long(result, "h2_goaway_count", 0) < 0 ||
            _set_double(result, "h2_stream_reset_ratio", 0.0) < 0) {
            Py_DECREF(result);
            result = NULL;
        }
    }
    return _attach_handle_stats(result, h);
#else
    if (use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
        tls_ctx = _tls_ctx_create_with_alpn(verify_tls ? 1 : 0, alpn_h2, sizeof(alpn_h2), &tls_reason);
        if (tls_ctx == NULL) {
            return _attach_handle_stats(_make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, "C_STATE_H2", "h2_transport_error", 0, 0), h);
        }
#else
        return _attach_handle_stats(_make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, "C_STATE_H2", "h2_transport_error", 0, 0), h);
#endif
    }

    conn_sample_cap = (total_attempts + h2_streams_per_conn - 1) / h2_streams_per_conn;
    if (conn_sample_cap > sample_cap_hard) {
        conn_sample_cap = sample_cap_hard;
    }
    if (conn_sample_cap > 0) {
        handshake_samples = (long long *)PyMem_Calloc((size_t)conn_sample_cap, sizeof(long long));
        if (handshake_samples == NULL) {
#ifdef SAMURAI_WITH_OPENSSL
            if (tls_ctx != NULL) {
                SSL_CTX_free(tls_ctx);
                tls_ctx = NULL;
            }
#endif
            return PyErr_NoMemory();
        }
    }

    plan_methods = _cfg_string_plan(cfg, "h2_request_plan_methods", total_attempts, H2_PLAN_METHOD_MAX_LEN, &plan_methods_used);
    if (plan_methods == NULL && PyErr_Occurred()) {
        result = NULL;
        goto finalize_h2;
    }
    plan_paths = _cfg_string_plan(cfg, "h2_request_plan_paths", total_attempts, H2_PLAN_PATH_MAX_LEN, &plan_paths_used);
    if (plan_paths == NULL && PyErr_Occurred()) {
        result = NULL;
        goto finalize_h2;
    }
    plan_user_agents = _cfg_string_plan(cfg, "h2_request_plan_user_agents", total_attempts, H2_PLAN_UA_MAX_LEN, &plan_uas_used);
    if (plan_user_agents == NULL && PyErr_Occurred()) {
        result = NULL;
        goto finalize_h2;
    }
    plan_items_used = plan_methods_used;
    if (plan_paths_used > plan_items_used) {
        plan_items_used = plan_paths_used;
    }
    if (plan_uas_used > plan_items_used) {
        plan_items_used = plan_uas_used;
    }
    if (plan_items_cfg > plan_items_used) {
        plan_items_used = plan_items_cfg;
    }
    if (plan_items_used > total_attempts) {
        plan_items_used = total_attempts;
    }

    run_start_ns = monotonic_ns_now();
    remaining = total_attempts;
    while (remaining > 0) {
        long need_conn = (remaining + h2_streams_per_conn - 1) / h2_streams_per_conn;
        long batch_conn = need_conn < h2_connections ? need_conn : h2_connections;
        if (batch_conn < 1) {
            batch_conn = 1;
        }
        if (batch_conn > peak_active) {
            peak_active = batch_conn;
        }
        for (long i = 0; i < batch_conn && remaining > 0; i++) {
            long reqs = remaining < h2_streams_per_conn ? remaining : h2_streams_per_conn;
            H2ConnResult conn_out;
            memset(&conn_out, 0, sizeof(conn_out));
            Py_BEGIN_ALLOW_THREADS
            _h2_run_connection(
                &addr,
                target_ip,
                (int)target_port,
                scheme,
                http_method,
                path,
                user_agent,
                plan_methods,
                plan_paths,
                plan_user_agents,
                plan_offset,
                reqs,
                timeout_ms,
                use_tls,
#ifdef SAMURAI_WITH_OPENSSL
                tls_ctx,
#endif
                server_name,
                &conn_out
            );
            Py_END_ALLOW_THREADS
            connections_used += 1;
            total_submitted += conn_out.submitted_count;
            sent_total += conn_out.sent;
            total_goaway += conn_out.goaway_count;
            total_rst += conn_out.rst_stream_count;
            if (conn_out.transport_error) {
                saw_transport_error = 1;
            }
            if (conn_out.protocol_error) {
                saw_protocol_error = 1;
            }
            if (handshake_samples != NULL &&
                conn_out.handshake_ns > 0 &&
                conn_out.sent > 0 &&
                sample_count < conn_sample_cap) {
                long copy_count = conn_out.sent;
                while (copy_count > 0 && sample_count < conn_sample_cap) {
                    handshake_samples[sample_count] = conn_out.handshake_ns;
                    sample_count += 1;
                    copy_count -= 1;
                }
            }
            remaining -= reqs;
            plan_offset += reqs;
        }
    }

    if (sent_total > total_attempts) {
        sent_total = total_attempts;
    }
    errors_total = total_attempts - sent_total;
    if (errors_total < 0) {
        errors_total = 0;
    }

    run_end_ns = monotonic_ns_now();
    if (run_end_ns > run_start_ns) {
        elapsed_s = (double)(run_end_ns - run_start_ns) / 1e9;
    }
    if (elapsed_s > 0.0) {
        conn_rate = (double)sent_total / elapsed_s;
    }

    if (sample_count > 0 && handshake_samples != NULL) {
        long p99_index;
        qsort(handshake_samples, (size_t)sample_count, sizeof(long long), _cmp_longlong);
        p99_index = (long)(0.99 * (double)(sample_count - 1));
        if (p99_index < 0) {
            p99_index = 0;
        }
        if (p99_index >= sample_count) {
            p99_index = sample_count - 1;
        }
        handshake_p99_ms = (double)handshake_samples[p99_index] / 1e6;
    }

    if (errors_total > 0) {
        if (saw_protocol_error || total_rst > 0 || total_goaway > 0) {
            final_reason = "h2_protocol_error";
        } else if (!use_tls && sent_total == 0 && total_submitted > 0 && saw_transport_error) {
            /*
             * h2c path submitted requests but received no valid H2 completion:
             * classify as protocol error (e.g. HTTP/1.x/plaintext peer).
             */
            final_reason = "h2_protocol_error";
        } else if (saw_transport_error) {
            final_reason = "h2_transport_error";
        } else {
            final_reason = "h2_transport_error";
        }
    }

    result = _make_result(
        total_attempts,
        sent_total,
        errors_total,
        peak_active,
        conn_rate,
        handshake_p99_ms,
        "C_STATE_H2",
        final_reason,
        0,
        0
    );
    if (result != NULL) {
        if (_set_long(result, "session_repeats", session_repeats) < 0 ||
            _set_long(result, "h2_connections_used", connections_used) < 0 ||
            _set_long(result, "h2_streams_per_conn", h2_streams_per_conn) < 0 ||
            _set_long(result, "h2_goaway_count", total_goaway) < 0 ||
            _set_long(result, "h2_stream_resets", total_rst) < 0 ||
            _set_long(result, "h2_request_plan_used", plan_items_used > 0 ? 1 : 0) < 0 ||
            _set_long(result, "h2_request_plan_items", plan_items_used) < 0 ||
            _set_double(result, "h2_stream_reset_ratio", total_attempts > 0 ? ((double)total_rst / (double)total_attempts) : 0.0) < 0 ||
            _set_str(result, "scheme", scheme) < 0) {
            Py_DECREF(result);
            result = NULL;
        }
    }

finalize_h2:
    _free_string_plan(plan_methods, total_attempts);
    _free_string_plan(plan_paths, total_attempts);
    _free_string_plan(plan_user_agents, total_attempts);
    PyMem_Free(handshake_samples);
#ifdef SAMURAI_WITH_OPENSSL
    if (tls_ctx != NULL) {
        SSL_CTX_free(tls_ctx);
        tls_ctx = NULL;
    }
    (void)tls_reason;
#endif
    if (result == NULL && PyErr_Occurred()) {
        return NULL;
    }
    return _attach_handle_stats(result, h);
#endif
}

#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_NGHTTP3)
typedef enum {
    QUIC_ATTEMPT_OK = 0,
    QUIC_ATTEMPT_CONNECT_FAIL = 1,
    QUIC_ATTEMPT_TLS_FAIL = 2,
    QUIC_ATTEMPT_STREAM_FAIL = 3,
    QUIC_ATTEMPT_CONNECT_TIMEOUT = 4,
    QUIC_ATTEMPT_TLS_TIMEOUT = 5
} QuicAttemptResult;

static QuicAttemptResult _quic_udp_attempt(
    const struct sockaddr_in *addr,
    const char *method,
    const char *path,
    long timeout_ms,
    int verify_tls,
    long stream_id
) {
    int fd = -1;
    char tx_buf[256];
    char rx_buf[256];
    ssize_t n = 0;
    struct timeval tv;

    if (addr == NULL) {
        return QUIC_ATTEMPT_CONNECT_FAIL;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return QUIC_ATTEMPT_CONNECT_FAIL;
    }
    if (timeout_ms < 1) {
        timeout_ms = 1;
    }
    tv.tv_sec = (time_t)(timeout_ms / 1000);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (const struct sockaddr *)addr, sizeof(*addr)) < 0) {
        int err = errno;
        close(fd);
        if (err == ETIMEDOUT) {
            return QUIC_ATTEMPT_CONNECT_TIMEOUT;
        }
        return QUIC_ATTEMPT_CONNECT_FAIL;
    }

    if (snprintf(
            tx_buf,
            sizeof(tx_buf),
            "QHS %s %s",
            (method != NULL && method[0] != '\0') ? method : "GET",
            (path != NULL && path[0] != '\0') ? path : "/"
        ) < 0) {
        close(fd);
        return QUIC_ATTEMPT_STREAM_FAIL;
    }
    if (send(fd, tx_buf, strlen(tx_buf), MSG_NOSIGNAL) <= 0) {
        int err = errno;
        close(fd);
        if (err == ETIMEDOUT || err == EAGAIN || err == EWOULDBLOCK) {
            return QUIC_ATTEMPT_CONNECT_TIMEOUT;
        }
        return QUIC_ATTEMPT_CONNECT_FAIL;
    }

    n = recv(fd, rx_buf, sizeof(rx_buf) - 1, 0);
    if (n <= 0) {
        int err = errno;
        close(fd);
        if (err == ETIMEDOUT || err == EAGAIN || err == EWOULDBLOCK) {
            return QUIC_ATTEMPT_TLS_TIMEOUT;
        }
        return QUIC_ATTEMPT_TLS_FAIL;
    }
    rx_buf[n] = '\0';
    if (verify_tls && strncmp(rx_buf, "QHS-OK", 6) != 0) {
        close(fd);
        return QUIC_ATTEMPT_TLS_FAIL;
    }

    if (snprintf(tx_buf, sizeof(tx_buf), "QST %ld", stream_id) < 0) {
        close(fd);
        return QUIC_ATTEMPT_STREAM_FAIL;
    }
    if (send(fd, tx_buf, strlen(tx_buf), MSG_NOSIGNAL) <= 0) {
        int err = errno;
        close(fd);
        if (err == ETIMEDOUT || err == EAGAIN || err == EWOULDBLOCK) {
            return QUIC_ATTEMPT_TLS_TIMEOUT;
        }
        return QUIC_ATTEMPT_STREAM_FAIL;
    }

    n = recv(fd, rx_buf, sizeof(rx_buf) - 1, 0);
    if (n <= 0) {
        close(fd);
        return QUIC_ATTEMPT_STREAM_FAIL;
    }
    rx_buf[n] = '\0';
    if (strncmp(rx_buf, "QST-OK", 6) != 0) {
        close(fd);
        return QUIC_ATTEMPT_STREAM_FAIL;
    }

    close(fd);
    return QUIC_ATTEMPT_OK;
}
#endif

static PyObject *l7_run_quic_stateful(PyObject *self, PyObject *args) {
    PyObject *cfg = NULL;
    PyObject *handle_obj = NULL;
    L7Handle *h = NULL;
    long count = 0;
    long session_repeats = 1;
    long total_attempts = 0;
    long target_port = 0;
    const char *target_ip = "";
    struct sockaddr_in addr;
    PyObject *result = NULL;
#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_NGHTTP3)
    long concurrency = 1;
    long retries = 0;
    long sent_total = 0;
    long errors_total = 0;
    long peak_active = 0;
    long connect_fail_count = 0;
    long connect_timeout_count = 0;
    long tls_fail_count = 0;
    long tls_timeout_count = 0;
    long stream_fail_count = 0;
    long retry_attempts = 0;
    long retry_successes = 0;
    long timeout_ms = 3000;
    double timeout_s = 3.0;
    double conn_rate = 0.0;
    double elapsed_s = 0.0;
    long long run_start_ns = 0;
    long long run_end_ns = 0;
    int verify_tls = 0;
    const char *scheme = "https";
    const char *path = "/";
    char method[24];
    const char *final_reason = "none";
    const char *stack_probe_reason = "not_checked";
#endif

    (void)self;

    if (PyArg_ParseTuple(args, "OO", &handle_obj, &cfg)) {
        h = _get_handle(handle_obj);
        if (h == NULL) {
            return NULL;
        }
        if (h->closed) {
            PyErr_SetString(PyExc_RuntimeError, "l7 handle is closed");
            return NULL;
        }
    } else {
        PyErr_Clear();
        if (!PyArg_ParseTuple(args, "O", &cfg)) {
            return NULL;
        }
    }

    if (!PyDict_Check(cfg)) {
        return _attach_handle_stats(_make_result(0, 0, 0, 0, 0.0, 0.0, "C_STATE_QUIC", "invalid_config", 0, 0), h);
    }

    count = _dict_long(cfg, "count", 0);
    session_repeats = _dict_long(cfg, "session_repeats", 1);
    if (session_repeats < 1) {
        session_repeats = 1;
    }
    if (count <= 0) {
        return _attach_handle_stats(_make_result(0, 0, 0, 0, 0.0, 0.0, "C_STATE_QUIC", "none", 0, 0), h);
    }
    if (count > LONG_MAX / session_repeats) {
        return _attach_handle_stats(_make_result(count, 0, count, 0, 0.0, 0.0, "C_STATE_QUIC", "count_overflow", 0, 0), h);
    }
    total_attempts = count * session_repeats;

    target_ip = _dict_cstr(cfg, "target_ip", "");
    target_port = _dict_long(cfg, "target_port", 443);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (target_ip[0] == '\0') {
        return _attach_handle_stats(_make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, "C_STATE_QUIC", "target_ip_missing", 0, 0), h);
    }
    if (target_port <= 0 || target_port > 65535) {
        return _attach_handle_stats(_make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, "C_STATE_QUIC", "target_port_invalid", 0, 0), h);
    }
    addr.sin_port = htons((uint16_t)target_port);
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) != 1) {
        return _attach_handle_stats(_make_result(total_attempts, 0, total_attempts, 0, 0.0, 0.0, "C_STATE_QUIC", "target_ip_invalid", 0, 0), h);
    }

#if !defined(SAMURAI_WITH_NGTCP2) || !defined(SAMURAI_WITH_NGHTTP3)
    result = _make_result(
        total_attempts,
        0,
        total_attempts,
        0,
        0.0,
        0.0,
        "C_STATE_QUIC",
        "quic_capability_unavailable",
        0,
        0
    );
    if (result != NULL) {
        if (_set_double(result, "quic_stream_fail_ratio", 1.0) < 0 ||
            _set_double(result, "quic_handshake_fail_ratio", 0.0) < 0) {
            Py_DECREF(result);
            result = NULL;
        }
    }
    return _attach_handle_stats(result, h);
#else
    if (!_quic_stack_probe(&stack_probe_reason)) {
        result = _make_result(
            total_attempts,
            0,
            total_attempts,
            0,
            0.0,
            0.0,
            "C_STATE_QUIC",
            "capability_unavailable",
            0,
            0
        );
        if (result != NULL) {
            if (_set_double(result, "quic_stream_fail_ratio", 1.0) < 0 ||
                _set_double(result, "quic_handshake_fail_ratio", 0.0) < 0 ||
                _set_str(result, "quic_stack_probe_reason", stack_probe_reason) < 0) {
                Py_DECREF(result);
                result = NULL;
            }
        }
        return _attach_handle_stats(result, h);
    }

    concurrency = _dict_long(cfg, "concurrency", 1);
    retries = _dict_long(cfg, "retries", 0);
    timeout_s = _dict_double(cfg, "timeout_s", 3.0);
    verify_tls = _dict_bool(cfg, "verify", 0);
    scheme = _dict_cstr(cfg, "scheme", "https");
    path = _dict_cstr(cfg, "quic_path", _dict_cstr(cfg, "http_path", "/"));
    _copy_upper_ascii(method, sizeof(method), _dict_cstr(cfg, "quic_method", _dict_cstr(cfg, "http_method", "GET")), "GET");

    if (concurrency < 1) {
        concurrency = 1;
    }
    if (concurrency > total_attempts) {
        concurrency = total_attempts;
    }
    if (concurrency < 1) {
        concurrency = 1;
    }
    if (retries < 0) {
        retries = 0;
    }
    if (retries > 8) {
        retries = 8;
    }
    if (timeout_s <= 0.0) {
        timeout_s = 3.0;
    }
    timeout_ms = (long)(timeout_s * 1000.0);
    if (timeout_ms < 10) {
        timeout_ms = 10;
    }
    peak_active = concurrency;

    run_start_ns = monotonic_ns_now();
    for (long stream_idx = 0; stream_idx < total_attempts; stream_idx++) {
        QuicAttemptResult last_fail = QUIC_ATTEMPT_STREAM_FAIL;
        int ok = 0;
        for (long attempt_idx = 0; attempt_idx <= retries; attempt_idx++) {
            QuicAttemptResult rc;
            if (attempt_idx > 0) {
                retry_attempts += 1;
            }
            Py_BEGIN_ALLOW_THREADS
            rc = _quic_udp_attempt(&addr, method, path, timeout_ms, verify_tls, stream_idx);
            Py_END_ALLOW_THREADS
            if (rc == QUIC_ATTEMPT_OK) {
                sent_total += 1;
                if (attempt_idx > 0) {
                    retry_successes += 1;
                }
                ok = 1;
                break;
            }
            last_fail = rc;
        }
        if (!ok) {
            if (last_fail == QUIC_ATTEMPT_CONNECT_FAIL || last_fail == QUIC_ATTEMPT_CONNECT_TIMEOUT) {
                connect_fail_count += 1;
                if (last_fail == QUIC_ATTEMPT_CONNECT_TIMEOUT) {
                    connect_timeout_count += 1;
                }
            } else if (last_fail == QUIC_ATTEMPT_TLS_FAIL || last_fail == QUIC_ATTEMPT_TLS_TIMEOUT) {
                tls_fail_count += 1;
                if (last_fail == QUIC_ATTEMPT_TLS_TIMEOUT) {
                    tls_timeout_count += 1;
                }
            } else {
                stream_fail_count += 1;
            }
        }
    }

    errors_total = total_attempts - sent_total;
    if (errors_total < 0) {
        errors_total = 0;
    }

    run_end_ns = monotonic_ns_now();
    if (run_end_ns > run_start_ns) {
        elapsed_s = (double)(run_end_ns - run_start_ns) / 1e9;
    }
    if (elapsed_s > 0.0) {
        conn_rate = (double)sent_total / elapsed_s;
    }

    if (errors_total > 0) {
        if (connect_fail_count >= tls_fail_count && connect_fail_count >= stream_fail_count) {
            final_reason = "connect_fail";
        } else if (tls_fail_count >= stream_fail_count) {
            final_reason = "tls_fail";
        } else {
            final_reason = "stream_fail";
        }
    }

    result = _make_result(
        total_attempts,
        sent_total,
        errors_total,
        peak_active,
        conn_rate,
        0.0,
        "C_STATE_QUIC",
        final_reason,
        retry_attempts,
        retry_successes
    );
    if (result != NULL) {
        if (_set_long(result, "session_repeats", session_repeats) < 0 ||
            _set_long(result, "retry_budget", retries) < 0 ||
            _set_long(result, "quic_connect_fail_count", connect_fail_count) < 0 ||
            _set_long(result, "quic_connect_timeout_count", connect_timeout_count) < 0 ||
            _set_long(result, "quic_tls_fail_count", tls_fail_count) < 0 ||
            _set_long(result, "quic_handshake_timeout_count", tls_timeout_count) < 0 ||
            _set_long(result, "quic_stream_fail_count", stream_fail_count) < 0 ||
            _set_double(result, "quic_stream_fail_ratio", total_attempts > 0 ? ((double)stream_fail_count / (double)total_attempts) : 0.0) < 0 ||
            _set_double(result, "quic_handshake_fail_ratio", total_attempts > 0 ? ((double)tls_fail_count / (double)total_attempts) : 0.0) < 0 ||
            _set_str(result, "scheme", scheme) < 0 ||
            _set_str(result, "quic_stack_probe_reason", stack_probe_reason) < 0) {
            Py_DECREF(result);
            result = NULL;
        }
    }
    return _attach_handle_stats(result, h);
#endif
}

static PyMethodDef L7Methods[] = {
    {"open", l7_open, METH_VARARGS, "open(config) -> handle"},
    {"close", l7_close, METH_VARARGS, "close(handle)"},
    {"snapshot", l7_snapshot, METH_VARARGS, "snapshot(handle) -> stats"},
    {"tls_supported", l7_tls_supported, METH_NOARGS, "tls_supported() -> bool"},
    {"h2_supported", l7_h2_supported, METH_NOARGS, "h2_supported() -> bool"},
    {"quic_supported", l7_quic_supported, METH_NOARGS, "quic_supported() -> bool"},
    {"run_http1_stateful", l7_run_http1_stateful, METH_VARARGS, "run_http1_stateful(config) -> stats"},
    {"run_websocket_stateful", l7_run_websocket_stateful, METH_VARARGS, "run_websocket_stateful(config) -> stats"},
    {"run_http2_stateful", l7_run_http2_stateful, METH_VARARGS, "run_http2_stateful(config) -> stats"},
    {"run_quic_stateful", l7_run_quic_stateful, METH_VARARGS, "run_quic_stateful(config) -> stats"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef l7_module = {
    PyModuleDef_HEAD_INIT,
    "l7_state_engine",
    "Samurai L7 state engine (epoll state machine)",
    -1,
    L7Methods
};

PyMODINIT_FUNC PyInit_l7_state_engine(void) {
    return PyModule_Create(&l7_module);
}
