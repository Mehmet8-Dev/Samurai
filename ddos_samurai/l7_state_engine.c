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
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef SAMURAI_WITH_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
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
    SESSION_READING = 4
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
#ifdef SAMURAI_WITH_OPENSSL
    SSL *ssl;
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

static SSL_CTX *_tls_ctx_create(int verify_peer, const char **reason_out) {
    SSL_CTX *ctx = NULL;
    static const unsigned char alpn_http11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

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

    (void)SSL_CTX_set_alpn_protos(ctx, alpn_http11, sizeof(alpn_http11));

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
    const TlsConfig *tls_cfg
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
#ifdef SAMURAI_WITH_OPENSSL
        s->ssl = SSL_new(tls_cfg->ctx);
        if (s->ssl == NULL) {
            close(fd);
            return -1;
        }
        if (SSL_set_fd(s->ssl, fd) != 1) {
            SSL_free(s->ssl);
            s->ssl = NULL;
            close(fd);
            return -1;
        }
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
        s->use_tls = 1;
        if (s->state == SESSION_SENDING) {
            s->state = SESSION_TLS_HANDSHAKE;
        }
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
    s->fd = fd;
    s->start_ns = now_ns;
    s->deadline_ns = now_ns + timeout_ns;
    return 0;
}

static int _session_progress(Session *s, uint32_t events, int websocket_mode) {
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
            s->state = s->use_tls ? SESSION_TLS_HANDSHAKE : SESSION_SENDING;
            continue;
        }

        if (s->state == SESSION_TLS_HANDSHAKE) {
#ifdef SAMURAI_WITH_OPENSSL
            int rc = SSL_connect(s->ssl);
            if (rc == 1) {
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
                    int wr = SSL_write(s->ssl, s->req + s->req_off, (int)(s->req_len - s->req_off));
                    if (wr > 0) {
                        s->req_off += (size_t)wr;
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
                n = SSL_read(s->ssl, s->resp + s->resp_len, (int)(sizeof(s->resp) - s->resp_len - 1));
                if (n < 0) {
                    int rd = SSL_get_error(s->ssl, (int)n);
                    if (rd == SSL_ERROR_WANT_READ || rd == SSL_ERROR_WANT_WRITE) {
                        return 0;
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
                    return status == 101 ? 1 : -1;
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
                    return status == 101 ? 1 : -1;
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

    sessions = (Session *)PyMem_Calloc((size_t)concurrency, sizeof(Session));
    if (sessions == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    for (long i = 0; i < concurrency; i++) {
        sessions[i].fd = -1;
    }

    event_cap = (int)(concurrency < 128 ? concurrency : 128);
    if (event_cap < 1) {
        event_cap = 1;
    }
    events = (struct epoll_event *)PyMem_Calloc((size_t)event_cap, sizeof(struct epoll_event));
    if (events == NULL) {
        PyMem_Free(sessions);
        PyErr_NoMemory();
        return -1;
    }

    epfd = epoll_create1(0);
    if (epfd < 0) {
        PyMem_Free(events);
        PyMem_Free(sessions);
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
                    tls_cfg
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

                    outcome = _session_progress(s, events[j].events, websocket_mode);
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
    PyMem_Free(events);
    PyMem_Free(sessions);

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
    long ws_ping_count;
    long ws_subscribe_count;
    const char *ws_auth_message;
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
        ws_ping_count = _dict_long(cfg, "ws_ping_count", 1);
        ws_subscribe_count = _dict_long(cfg, "ws_subscribe_count", 0);
        ws_auth_message = _dict_cstr(cfg, "ws_auth_message", "");
        ws_await_response = _dict_bool(cfg, "ws_await_response", 0);
        if (ws_ping_count > 1 || ws_subscribe_count > 0 || ws_auth_message[0] != '\0' || ws_await_response) {
            return _attach_handle_stats(
                _make_result(
                    total_attempts,
                    0,
                    total_attempts,
                    0,
                    0.0,
                    0.0,
                    sender_path,
                    "ws_scenario_unsupported",
                    0,
                    0
                ),
                handle
            );
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

        pass.sent = 0;
        pass.errors = current;
        pass.peak_active = 0;
        pass.fatal_loop_error = 0;

        if (pass_idx > 0) {
            retry_attempts += current;
        }

        if (_run_single_pass(
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
                latency_samples,
                latency_sample_cap,
                &latency_sample_count,
                &pass
            ) < 0) {
#ifdef SAMURAI_WITH_OPENSSL
            if (tls_cfg.ctx != NULL) {
                SSL_CTX_free(tls_cfg.ctx);
                tls_cfg.ctx = NULL;
            }
#endif
            PyMem_Free(latency_samples);
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

static PyMethodDef L7Methods[] = {
    {"open", l7_open, METH_VARARGS, "open(config) -> handle"},
    {"close", l7_close, METH_VARARGS, "close(handle)"},
    {"snapshot", l7_snapshot, METH_VARARGS, "snapshot(handle) -> stats"},
    {"tls_supported", l7_tls_supported, METH_NOARGS, "tls_supported() -> bool"},
    {"run_http1_stateful", l7_run_http1_stateful, METH_VARARGS, "run_http1_stateful(config) -> stats"},
    {"run_websocket_stateful", l7_run_websocket_stateful, METH_VARARGS, "run_websocket_stateful(config) -> stats"},
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
