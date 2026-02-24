import numpy as np
from numba import cuda

@cuda.jit
def test_kernel(arr):
    arr.view(np.uint16)[0] = 0xABCD
    arr.view(np.uint32)[1] = 0x12345678

arr = np.zeros(8, dtype=np.uint8)
test_kernel[1, 1](arr)
print("Output array:", [hex(x) for x in arr])
