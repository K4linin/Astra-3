"""
Target: calculate_checksum
Фаззинг контрольных сумм: CRC32, MD5, SHA, Fletcher
"""

import hashlib
import struct
import sys
import zlib
from typing import Any, Dict


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def md5_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha1_hash(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def simple_checksum(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF


def xor_checksum(data: bytes) -> int:
    result = 0
    for byte in data:
        result ^= byte
    return result


def fletcher16(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    
    for byte in data[:10000]:
        sum1 = (sum1 + byte) % 255
        sum2 = (sum2 + sum1) % 255
    
    return (sum2 << 8) | sum1


def fletcher32(data: bytes) -> int:
    sum1 = 0
    sum2 = 0
    
    for i in range(0, min(len(data) - 3, 10000), 4):
        word = struct.unpack('<I', data[i:i+4])[0]
        sum1 = (sum1 + word) % 65535
        sum2 = (sum2 + sum1) % 65535
    
    return (sum2 << 16) | sum1


def internet_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'
    
    total = 0
    for i in range(0, len(data), 2):
        word = struct.unpack('>H', data[i:i+2])[0]
        total += word
    
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    
    return ~total & 0xFFFF


def verify_checksum(data: bytes, expected: int, algorithm: str) -> bool:
    algorithms = {
        'crc32': crc32,
        'adler32': adler32,
        'simple': simple_checksum,
        'xor': xor_checksum,
        'fletcher16': fletcher16,
        'internet': internet_checksum
    }
    
    func = algorithms.get(algorithm)
    if func is None:
        return False
    
    try:
        computed = func(data)
        return computed == expected
    except:
        return False


def parse_checksum_request(data: bytes) -> Dict[str, Any]:
    result = {
        'algorithm': None,
        'checksum': None,
        'verified': None
    }
    
    if len(data) < 2:
        return result
    
    algo_code = data[0]
    algo_map = {
        0x00: 'crc32',
        0x01: 'adler32',
        0x02: 'simple',
        0x03: 'xor',
        0x04: 'fletcher16',
        0x05: 'internet',
        0x10: 'md5',
        0x11: 'sha1',
        0x12: 'sha256'
    }
    
    algorithm = algo_map.get(algo_code)
    if algorithm is None:
        return result
    
    result['algorithm'] = algorithm
    payload = data[1:]
    
    try:
        if algorithm == 'crc32':
            result['checksum'] = crc32(payload)
        elif algorithm == 'adler32':
            result['checksum'] = adler32(payload)
        elif algorithm == 'simple':
            result['checksum'] = simple_checksum(payload)
        elif algorithm == 'xor':
            result['checksum'] = xor_checksum(payload)
        elif algorithm == 'fletcher16':
            result['checksum'] = fletcher16(payload)
        elif algorithm == 'internet':
            result['checksum'] = internet_checksum(payload)
        elif algorithm == 'md5':
            result['checksum'] = md5_hash(payload)
        elif algorithm == 'sha1':
            result['checksum'] = sha1_hash(payload)
        elif algorithm == 'sha256':
            result['checksum'] = sha256_hash(payload)
    except Exception:
        pass
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        _ = crc32(data)
    except:
        pass
    
    try:
        _ = adler32(data)
    except:
        pass
    
    try:
        _ = simple_checksum(data)
    except:
        pass
    
    try:
        _ = xor_checksum(data)
    except:
        pass
    
    try:
        _ = fletcher16(data)
    except:
        pass
    
    try:
        _ = internet_checksum(data)
    except:
        pass
    
    try:
        _ = md5_hash(data[:100000])
    except:
        pass
    
    try:
        _ = sha1_hash(data[:100000])
    except:
        pass
    
    try:
        _ = sha256_hash(data[:100000])
    except:
        pass
    
    try:
        _ = parse_checksum_request(data)
    except:
        pass


if __name__ == '__main__':
    try:
        import atheris
        atheris.Setup(sys.argv, lambda d: fuzz_target(d))
        atheris.Fuzz()
    except ImportError:
        print("atheris not installed")