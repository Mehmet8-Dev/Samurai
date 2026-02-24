import numpy as np
from numba import cuda

@cuda.jit
def test_kernel(arr, out):
    idx = cuda.grid(1)
    if idx < 10:
        val = 0
        if (idx & 1) == 0:
            val = arr.view(np.uint32)[0]
        out[idx] = val

arr = np.zeros(790, dtype=np.uint8)
out = np.zeros(10, dtype=np.uint32)
try:
    test_kernel[1, 32](arr, out)
    print("Output:", out)
except Exception as e:
    print("Exception on CPU:", e)
