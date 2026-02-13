"""
Target: compress_image
Фаззинг-обертка для сжатия изображений
"""

import struct
import sys
import zlib
from typing import Any, Dict, Optional, Tuple


def parse_png_header(data: bytes) -> Optional[Dict[str, Any]]:
    """Парсинг PNG заголовка"""
    if len(data) < 8:
        return None
    
    png_signature = b'\x89PNG\r\n\x1a\n'
    if data[:8] != png_signature:
        return None
    
    if len(data) < 33:
        return None
    
    # IHDR chunk
    length = struct.unpack('>I', data[8:12])[0]
    chunk_type = data[12:16]
    
    if chunk_type != b'IHDR' or length != 13:
        return None
    
    width = struct.unpack('>I', data[16:20])[0]
    height = struct.unpack('>I', data[20:24])[0]
    bit_depth = data[24]
    color_type = data[25]
    
    return {
        'width': width,
        'height': height,
        'bit_depth': bit_depth,
        'color_type': color_type,
        'valid': width > 0 and height > 0 and width < 100000 and height < 100000
    }


def parse_jpeg_header(data: bytes) -> Optional[Dict[str, Any]]:
    """Парсинг JPEG заголовка"""
    if len(data) < 4:
        return None
    
    if data[:2] != b'\xff\xd8':
        return None
    
    return {'format': 'JPEG', 'valid': True}


def compress_rle(data: bytes) -> bytes:
    """RLE сжатие"""
    if not data:
        return b''
    
    result = []
    count = 1
    prev = data[0]
    
    for byte in data[1:10000]:  # Limit input size
        if byte == prev and count < 255:
            count += 1
        else:
            result.append(count)
            result.append(prev)
            prev = byte
            count = 1
    
    result.append(count)
    result.append(prev)
    
    return bytes(result)


def decompress_rle(data: bytes) -> bytes:
    """RLE декомпрессия"""
    if len(data) < 2:
        return b''
    
    result = []
    
    for i in range(0, min(len(data) - 1, 10000), 2):
        count = data[i]
        byte = data[i + 1]
        result.extend([byte] * min(count, 1000))
    
    return bytes(result)


def compress_zlib(data: bytes) -> bytes:
    """Zlib сжатие"""
    return zlib.compress(data[:100000], level=6)


def decompress_zlib(data: bytes) -> bytes:
    """Zlib декомпрессия"""
    try:
        return zlib.decompress(data[:100000])
    except zlib.error:
        return b''


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    # 1. PNG parsing
    try:
        _ = parse_png_header(data)
    except struct.error:
        pass
    
    # 2. JPEG parsing
    try:
        _ = parse_jpeg_header(data)
    except:
        pass
    
    # 3. RLE compression
    try:
        compressed = compress_rle(data)
        decompressed = decompress_rle(compressed)
    except MemoryError:
        pass
    
    # 4. Zlib compression
    try:
        compressed = compress_zlib(data)
        decompressed = decompress_zlib(compressed)
    except (zlib.error, MemoryError):
        pass


if __name__ == '__main__':
    try:
        import atheris
        atheris.Setup(sys.argv, lambda d: fuzz_target(d))
        atheris.Fuzz()
    except ImportError:
        print("atheris not installed")