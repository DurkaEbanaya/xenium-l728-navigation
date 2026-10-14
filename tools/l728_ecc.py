"""L728 host BCH encoder: GF(2^14), t=12, 168 parity bits per 1024 bytes.

The reciprocal generator/order is verified against BootROM-generated snapshots.
This implements encoding and parity verification, not error correction.
"""
GENERATOR = 0x160d461998eaf3c76bd7459fa40188bacd5254bba09
BITS = 168
MASK = (1 << BITS) - 1


def _remainder(value):
    while value.bit_length() > BITS:
        value ^= GENERATOR << (value.bit_length() - BITS - 1)
    return value


TABLE = tuple(_remainder(byte << BITS) for byte in range(256))


def parity(main):
    if len(main) != 1024:
        raise ValueError("Expected a 1024-byte main sector")
    remainder = 0
    # Hardware feeds bit/byte order equivalent to a little-endian main integer
    # followed by 168 zero bits; the parity field is stored big-endian.
    for byte in reversed(main):
        remainder = ((remainder << 8) & MASK) ^ TABLE[(remainder >> (BITS - 8)) ^ byte]
    return remainder.to_bytes(21, "big")


def encode_page(page):
    if len(page) != 2112:
        raise ValueError("Expected one packed 2048+64 page")
    result = bytearray(page)
    for sector in range(2):
        main = page[sector * 1024:(sector + 1) * 1024]
        offset = 2048 + sector * 32 + 4
        result[offset:offset + 21] = parity(main)
    return bytes(result)


def validate_block(block, parity_error_limit=0):
    if len(block) != 64 * 2112:
        raise ValueError("Expected one 64-page block")
    discrepancies = []
    for page in range(64):
        for sector in range(2):
            start = page * 2112
            main = block[start + sector * 1024:start + (sector + 1) * 1024]
            spare = block[start + 2048 + sector * 32:start + 2048 + (sector + 1) * 32]
            if main == b"\xff" * 1024 and spare == b"\xff" * 32:
                continue
            expected = parity(main)
            errors = sum((a ^ b).bit_count() for a, b in zip(expected, spare[4:25]))
            if errors > parity_error_limit:
                raise ValueError(f"Invalid BCH parity at page {page}, sector {sector}: {errors} differing bits")
            if errors:
                discrepancies.append((page, sector, errors))
    return discrepancies
