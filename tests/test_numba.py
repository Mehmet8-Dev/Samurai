import numpy as np
from numba import cuda

@cuda.jit(device=True)
def write_uint32_be(buffer, offset, value):
    if (offset & 0x3) == 0:
        bswap_val = ((value & 0xFF) << 24) | ((value & 0xFF00) << 8) | ((value & 0xFF0000) >> 8) | ((value >> 24) & 0xFF)
        buffer.view(np.uint32)[offset >> 2] = bswap_val
    else:
        buffer[offset] = (value >> 24) & 0xFF
        buffer[offset + 1] = (value >> 16) & 0xFF
        buffer[offset + 2] = (value >> 8) & 0xFF
        buffer[offset + 3] = value & 0xFF

@cuda.jit
def test_kernel(arr):
    write_uint32_be(arr, 0, 0x12345678)
    write_uint32_be(arr, 1, 0x9ABCDEF0)

arr = np.zeros(8, dtype=np.uint8)
try:
    test_kernel[1, 1](arr)
    print("Success:", [hex(x) for x in arr])
except Exception as e:
    print("Error:", e)
