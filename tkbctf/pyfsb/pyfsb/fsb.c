#include <Python.h>

static PyObject *pwn(PyObject *self, PyObject *args) {
  char request[0x100];
  if (fgets(request, 0x100, stdin) == NULL)
    return NULL;
  request[strcspn(request, "\n")] = 0;

  return Py_BuildValue(request);
}

static PyMethodDef FsbMethods[] = {{"pwn", pwn, METH_VARARGS, NULL}, {NULL, NULL, 0, NULL}};
static struct PyModuleDef fsb_mod = {PyModuleDef_HEAD_INIT, "fsb", NULL, -1, FsbMethods};

PyMODINIT_FUNC PyInit_fsb(void) { return PyModule_Create(&fsb_mod); }