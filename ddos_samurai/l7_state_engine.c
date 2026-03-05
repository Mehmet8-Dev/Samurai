#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    long id;
    long sessions_total;
    long sessions_ok;
    long sessions_err;
    int closed;
} L7Handle;

typedef enum {
    SESSION_CONNECTING = 1,
    SESSION_SENDING = 2,
    SESSION_READING = 3
} SessionState;

typedef struct {
    int in_use;
    int fd;
    SessionState state;
    size_t req_len;
    size_t req_off;
    size_t resp_len;
    char req[1024];
    char resp[2048];
    long long start_ns;
    long long deadline_ns;
} Session;

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
        n = snprintf(
            s->req,
            sizeof(s->req),
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: close\r\n"
            "User-Agent: DDoSamurai-L7/1.0\r\n"
            "\r\n",
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
    int websocket_mode
) {
    int fd;
    int rc;
    struct epoll_event ev;

    memset(s, 0, sizeof(*s));
    s->fd = -1;

    if (_build_request(s, target_ip, target_port, path, websocket_mode) < 0) {
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
            s->state = SESSION_SENDING;
            continue;
        }

        if (s->state == SESSION_SENDING) {
            while (s->req_off < s->req_len) {
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
            s->state = SESSION_READING;
            continue;
        }

        if (s->state == SESSION_READING) {
            n = recv(s->fd, s->resp + s->resp_len, sizeof(s->resp) - s->resp_len - 1, 0);
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
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }

        return -1;
    }
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

static PyObject *_run_state_machine(PyObject *cfg, int websocket_mode, const char *sender_path) {
    long count;
    long concurrency;
    long max_active_sessions;
    double timeout_s;
    const char *target_ip;
    long target_port;
    const char *path;
    struct sockaddr_in addr;
    int epfd = -1;
    Session *sessions = NULL;
    struct epoll_event *events = NULL;
    int event_cap;
    long launched = 0;
    long completed = 0;
    long active = 0;
    long peak_active = 0;
    long sent = 0;
    long errors = 0;
    long long run_start_ns;
    long long now_ns;
    long long timeout_ns;
    const long sample_cap_hard = 200000;
    long latency_sample_cap;
    long latency_sample_count = 0;
    long long *latency_samples = NULL;
    int fatal_loop_error = 0;

    if (!PyDict_Check(cfg)) {
        return _make_result(0, 0, 0, 0, 0.0, 0.0, sender_path, "invalid_config", 0, 0);
    }

    count = _dict_long(cfg, "count", 0);
    concurrency = _dict_long(cfg, "concurrency", 1);
    max_active_sessions = _dict_long(cfg, "max_active_sessions", 0);
    timeout_s = _dict_double(cfg, "timeout_s", websocket_mode ? 3.0 : 5.0);
    target_ip = _dict_cstr(cfg, "target_ip", "");
    target_port = _dict_long(cfg, "target_port", websocket_mode ? 80 : 80);
    path = _dict_cstr(cfg, websocket_mode ? "ws_path" : "http_path", "/");

    if (count <= 0) {
        return _make_result(0, 0, 0, 0, 0.0, 0.0, sender_path, "none", 0, 0);
    }
    if (concurrency < 1) {
        concurrency = 1;
    }
    if (max_active_sessions > 0 && concurrency > max_active_sessions) {
        concurrency = max_active_sessions;
    }
    if (concurrency > count) {
        concurrency = count;
    }
    if (concurrency < 1) {
        concurrency = 1;
    }
    if (timeout_s <= 0.0) {
        timeout_s = websocket_mode ? 3.0 : 5.0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)target_port);
    if (target_ip[0] == '\0') {
        return _make_result(count, 0, count, 0, 0.0, 0.0, sender_path, "target_ip_missing", 0, 0);
    }
    if (target_port <= 0 || target_port > 65535) {
        return _make_result(count, 0, count, 0, 0.0, 0.0, sender_path, "target_port_invalid", 0, 0);
    }
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) != 1) {
        return _make_result(count, 0, count, 0, 0.0, 0.0, sender_path, "target_ip_invalid", 0, 0);
    }

    timeout_ns = (long long)(timeout_s * 1000000000.0);
    if (timeout_ns < 1000000LL) {
        timeout_ns = 1000000LL;
    }

    sessions = (Session *)PyMem_Calloc((size_t)concurrency, sizeof(Session));
    if (sessions == NULL) {
        return PyErr_NoMemory();
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
        return PyErr_NoMemory();
    }

    latency_sample_cap = count < sample_cap_hard ? count : sample_cap_hard;
    if (latency_sample_cap > 0) {
        latency_samples = (long long *)PyMem_Calloc((size_t)latency_sample_cap, sizeof(long long));
        if (latency_samples == NULL) {
            PyMem_Free(events);
            PyMem_Free(sessions);
            return PyErr_NoMemory();
        }
    }

    epfd = epoll_create1(0);
    if (epfd < 0) {
        PyMem_Free(latency_samples);
        PyMem_Free(events);
        PyMem_Free(sessions);
        return _make_result(count, 0, count, 0, 0.0, 0.0, sender_path, "epoll_create_failed", 0, 0);
    }

    run_start_ns = monotonic_ns_now();

    while (completed < count) {
        long i;

        now_ns = monotonic_ns_now();

        for (i = 0; i < concurrency && launched < count && active < concurrency; i++) {
            Session *slot = &sessions[i];
            if (slot->in_use) {
                continue;
            }

            launched += 1;
            if (_session_start(
                    slot,
                    epfd,
                    &addr,
                    now_ns,
                    timeout_ns,
                    target_ip,
                    (int)target_port,
                    path,
                    websocket_mode
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

        if (active <= 0 && launched >= count) {
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
                        if (latency_samples != NULL && latency_sample_count < latency_sample_cap) {
                            latency_samples[latency_sample_count++] = fin_ns - s->start_ns;
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

    if (completed < count) {
        errors += (count - completed);
        completed = count;
    }

    close(epfd);

    {
        long long run_end_ns = monotonic_ns_now();
        double elapsed_s = 0.0;
        double conn_rate = 0.0;
        double handshake_p99_ms = 0.0;
        PyObject *result;

        if (run_end_ns > run_start_ns) {
            elapsed_s = (double)(run_end_ns - run_start_ns) / 1e9;
        }
        if (elapsed_s > 0.0) {
            conn_rate = (double)sent / elapsed_s;
        }

        if (latency_sample_count > 0) {
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

        result = _make_result(
            count,
            sent,
            errors,
            peak_active,
            conn_rate,
            handshake_p99_ms,
            sender_path,
            fatal_loop_error ? "epoll_loop_failed" : "none",
            0,
            0
        );

        PyMem_Free(latency_samples);
        PyMem_Free(events);
        PyMem_Free(sessions);
        return result;
    }
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
        _set_long(out, "sessions_total", h->sessions_total) < 0 ||
        _set_long(out, "sessions_ok", h->sessions_ok) < 0 ||
        _set_long(out, "sessions_err", h->sessions_err) < 0 ||
        _set_long(out, "closed", h->closed ? 1 : 0) < 0) {
        Py_DECREF(out);
        return NULL;
    }

    return out;
}

static PyObject *l7_run_http1_stateful(PyObject *self, PyObject *args) {
    PyObject *cfg = NULL;

    (void)self;

    if (!PyArg_ParseTuple(args, "O", &cfg)) {
        return NULL;
    }

    return _run_state_machine(cfg, 0, "C_STATE_HTTP1");
}

static PyObject *l7_run_websocket_stateful(PyObject *self, PyObject *args) {
    PyObject *cfg = NULL;

    (void)self;

    if (!PyArg_ParseTuple(args, "O", &cfg)) {
        return NULL;
    }

    return _run_state_machine(cfg, 1, "C_STATE_WS");
}

static PyMethodDef L7Methods[] = {
    {"open", l7_open, METH_VARARGS, "open(config) -> handle"},
    {"close", l7_close, METH_VARARGS, "close(handle)"},
    {"snapshot", l7_snapshot, METH_VARARGS, "snapshot(handle) -> stats"},
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
