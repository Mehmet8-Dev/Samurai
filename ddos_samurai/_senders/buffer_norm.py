import numpy as np

from .. import utils

log_error = utils.log_error


def _normalize_packets_buffer(
    packets_buffer,
    required_bytes: int,
    pool_key: str,
    *,
    return_meta: bool = False,
):
    """
    Normalize packet buffer for TX paths.
    - If a GPU array is provided, copy once into shared pinned host pool.
    - If a NumPy array is non-contiguous, compact it (prefer pinned pool).
    """
    meta = {"buffer_copy_count": 0, "buffer_copy_bytes": 0}

    def _ret(buf):
        if return_meta:
            return buf, meta
        return buf

    if required_bytes <= 0:
        return _ret(packets_buffer)

    # CUDA array interface (CuPy / Numba device arrays, etc.)
    if hasattr(packets_buffer, "__cuda_array_interface__"):
        try:
            from .. import gpu_packet
            out = gpu_packet.copy_gpu_to_host_pinned(packets_buffer, key=pool_key, blocking=True)
            meta["buffer_copy_count"] = 1
            meta["buffer_copy_bytes"] = int(required_bytes)
            return _ret(out)
        except Exception as e:
            log_error(f"GPU->host normalize failed, using fallback copy: {e}")
            try:
                # Fallback for CuPy-like arrays
                out = packets_buffer.get()
                meta["buffer_copy_count"] = 1
                meta["buffer_copy_bytes"] = int(required_bytes)
                return _ret(out)
            except Exception:
                pass

    # Normalize memoryview into byte-addressable shape if needed
    if isinstance(packets_buffer, memoryview):
        if packets_buffer.itemsize != 1:
            packets_buffer = packets_buffer.cast("B")
        return _ret(packets_buffer)

    if isinstance(packets_buffer, np.ndarray):
        flat = np.ravel(packets_buffer)
        if flat.dtype != np.uint8:
            if flat.dtype.itemsize == 1:
                flat = flat.view(np.uint8)
            else:
                flat = flat.astype(np.uint8, copy=False)

        if flat.size < required_bytes:
            raise ValueError(
                f"Packet buffer too small: {flat.size} < required {required_bytes} bytes"
            )

        flat = flat[:required_bytes]
        if flat.flags.c_contiguous:
            return _ret(flat)

        try:
            from .. import gpu_packet
            out = gpu_packet.get_pinned_host_pool().acquire(required_bytes, dtype=np.uint8, key=pool_key)
            out[:required_bytes] = flat
            meta["buffer_copy_count"] = 1
            meta["buffer_copy_bytes"] = int(required_bytes)
            return _ret(out[:required_bytes])
        except Exception:
            out = np.ascontiguousarray(flat)
            meta["buffer_copy_count"] = 1
            meta["buffer_copy_bytes"] = int(required_bytes)
            return _ret(out)

    return _ret(packets_buffer)

