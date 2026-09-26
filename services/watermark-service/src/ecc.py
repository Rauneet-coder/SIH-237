"""
Reed-Solomon Error Correction Code (ECC) Module
Provides forward error correction for watermark payloads to survive
compression, optical distortion, and transmission noise.
"""

import reedsolo

class WatermarkECC:
    def __init__(self, nsym: int = 16):
        """
        nsym: Number of error correction bytes (can correct up to nsym // 2 byte errors)
        """
        self.nsym = nsym
        self.rs = reedsolo.RSCodec(nsym)

    def encode(self, payload: bytes) -> bytes:
        """Encode binary payload with Reed-Solomon parity symbols."""
        return bytes(self.rs.encode(bytearray(payload)))

    def decode(self, encoded: bytes) -> tuple[bytes, int]:
        """
        Decode and correct errors in binary payload.
        Returns: (corrected_payload, corrected_err_count)
        """
        try:
            decoded, _, errata_pos = self.rs.decode(bytearray(encoded))
            return bytes(decoded), len(errata_pos)
        except reedsolo.ReedSolomonError as e:
            raise ValueError(f"Unrecoverable bit errors exceed ECC capacity: {e}")

# Default shared singleton with 16 parity bytes
default_ecc = WatermarkECC(nsym=16)
