#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdint.h>


typedef struct {
    long id;
    long attempted;
    long sent;
    long errors;
    long batches;
    int closed;
    char backend[32];
} DpHandle;


static long g_next_id = 1;


static void _capsule_destructor(PyObject *capsule) {
    DpHandle *h = (DpHandle *)PyCapsule_GetPointer(capsule, "samurai.dataplane.handle");
    if (h != NULL) {
        PyMem_Free(h);
    }
}


static DpHandle *_get_handle(PyObject *obj) {
    return (DpHandle *)PyCapsule_GetPointer(obj, "samurai.dataplane.handle");
}


static PyObject *dp_open(PyObject *self, PyObject *args) {
    PyObject *cfg = NULL;
    DpHandle *h = NULL;
    const char *backend = "auto";

    if (!PyArg_ParseTuple(args, "O", &cfg)) {
        return NULL;
    }

    h = (DpHandle *)PyMem_Calloc(1, sizeof(DpHandle));
    if (h == NULL) {
        return PyErr_NoMemory();
    }

    h->id = g_next_id++;

    if (PyDict_Check(cfg)) {
        PyObject *backend_obj = PyDict_GetItemString(cfg, "backend");
        if (backend_obj != NULL) {
            backend = PyUnicode_AsUTF8(backend_obj);
            if (backend == NULL) {
                PyMem_Free(h);
                return NULL;
            }
        }
    }

    if (backend == NULL) {
        backend = "auto";
    }

    (void)snprintf(h->backend, sizeof(h->backend), "%s", backend);

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

    h->attempted += (long)count;
    h->sent += (long)count;
    h->errors += 0;
    h->batches += 1;

    out = PyDict_New();
    if (out == NULL) {
        return NULL;
    }

    PyDict_SetItemString(out, "attempted", PyLong_FromLong(count));
    PyDict_SetItemString(out, "sent", PyLong_FromLong(count));
    PyDict_SetItemString(out, "errors", PyLong_FromLong(0));
    PyDict_SetItemString(out, "bytes_sent_est", PyLong_FromLong((long)count * (long)packet_size));

    if (h->backend[0] != '\0') {
        if (strcmp(h->backend, "xdp") == 0) {
            PyDict_SetItemString(out, "sender_path", PyUnicode_FromString("DP_XDP"));
        } else if (strcmp(h->backend, "txring") == 0) {
            PyDict_SetItemString(out, "sender_path", PyUnicode_FromString("DP_TX_RING"));
        } else if (strcmp(h->backend, "c_ext_l3") == 0) {
            PyDict_SetItemString(out, "sender_path", PyUnicode_FromString("DP_C_EXT_L3"));
        } else {
            PyDict_SetItemString(out, "sender_path", PyUnicode_FromString("DP_CORE"));
        }
    } else {
        PyDict_SetItemString(out, "sender_path", PyUnicode_FromString("DP_CORE"));
    }

    PyDict_SetItemString(out, "sender_fallback_reason", PyUnicode_FromString("none"));
    PyDict_SetItemString(out, "fallback_count", PyLong_FromLong(0));
    PyDict_SetItemString(out, "target_ip", PyUnicode_FromString(target_ip != NULL ? target_ip : ""));
    PyDict_SetItemString(out, "target_port", PyLong_FromLong(target_port));
    PyDict_SetItemString(out, "packet_size", PyLong_FromLong(packet_size));

    (void)buffer_obj;
    return out;
}


static PyObject *dp_snapshot(PyObject *self, PyObject *args) {
    PyObject *handle_obj = NULL;
    DpHandle *h = NULL;
    PyObject *out = NULL;

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

    PyDict_SetItemString(out, "id", PyLong_FromLong(h->id));
    PyDict_SetItemString(out, "attempted", PyLong_FromLong(h->attempted));
    PyDict_SetItemString(out, "sent", PyLong_FromLong(h->sent));
    PyDict_SetItemString(out, "errors", PyLong_FromLong(h->errors));
    PyDict_SetItemString(out, "batches", PyLong_FromLong(h->batches));
    PyDict_SetItemString(out, "backend", PyUnicode_FromString(h->backend));
    PyDict_SetItemString(out, "closed", PyLong_FromLong(h->closed ? 1 : 0));

    return out;
}


static PyObject *dp_close(PyObject *self, PyObject *args) {
    PyObject *handle_obj = NULL;
    DpHandle *h = NULL;

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
    "Samurai dataplane core (scaffold)",
    -1,
    DataplaneMethods
};


PyMODINIT_FUNC PyInit_dataplane_core(void) {
    return PyModule_Create(&dataplane_module);
}
