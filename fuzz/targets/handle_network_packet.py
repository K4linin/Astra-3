"""
Target: handle_network_packet
Фаззинг-обертка для обработки сетевых пакетов
"""

import struct
import sys
from typing import Any, Dict, Optional, Tuple


class PacketParseError(Exception):
    pass


def parse_ethernet_header(data: bytes) -> Dict[str, Any]:
    """Парсинг Ethernet заголовка"""
    if len(data) < 14:
        raise PacketParseError("Too short for Ethernet header")
    
    dst_mac = data[:6]
    src_mac = data[6:12]
    ethertype = struct.unpack('>H', data[12:14])[0]
    
    return {
        'dst_mac': ':'.join(f'{b:02x}' for b in dst_mac),
        'src_mac': ':'.join(f'{b:02x}' for b in src_mac),
        'ethertype': ethertype,
        'payload': data[14:]
    }


def parse_ip_header(data: bytes) -> Dict[str, Any]:
    """Парсинг IPv4 заголовка"""
    if len(data) < 20:
        raise PacketParseError("Too short for IPv4 header")
    
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    
    if version != 4:
        raise PacketParseError(f"Not IPv4: version={version}")
    
    header_length = ihl * 4
    if len(data) < header_length:
        raise PacketParseError("Truncated IPv4 header")
    
    total_length = struct.unpack('>H', data[2:4])[0]
    protocol = data[9]
    src_ip = '.'.join(str(b) for b in data[12:16])
    dst_ip = '.'.join(str(b) for b in data[16:20])
    
    return {
        'version': version,
        'header_length': header_length,
        'total_length': total_length,
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'payload': data[header_length:]
    }


def parse_tcp_header(data: bytes) -> Dict[str, Any]:
    """Парсинг TCP заголовка"""
    if len(data) < 20:
        raise PacketParseError("Too short for TCP header")
    
    src_port, dst_port = struct.unpack('>HH', data[0:4])
    seq_num = struct.unpack('>I', data[4:8])[0]
    ack_num = struct.unpack('>I', data[8:12])[0]
    flags = data[13]
    
    data_offset = (data[12] >> 4) * 4
    
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq_num': seq_num,
        'ack_num': ack_num,
        'flags': {
            'fin': bool(flags & 0x01),
            'syn': bool(flags & 0x02),
            'rst': bool(flags & 0x04),
            'psh': bool(flags & 0x08),
            'ack': bool(flags & 0x10),
            'urg': bool(flags & 0x20)
        },
        'data_offset': data_offset,
        'payload': data[data_offset:] if len(data) > data_offset else b''
    }


def parse_udp_header(data: bytes) -> Dict[str, Any]:
    """Парсинг UDP заголовка"""
    if len(data) < 8:
        raise PacketParseError("Too short for UDP header")
    
    src_port, dst_port, length, checksum = struct.unpack('>HHHH', data[0:8])
    
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'length': length,
        'checksum': checksum,
        'payload': data[8:]
    }


def process_packet(data: bytes) -> Dict[str, Any]:
    """Обработка сетевого пакета"""
    result = {'layers': []}
    
    try:
        # Ethernet
        eth = parse_ethernet_header(data)
        result['layers'].append(('ethernet', eth))
        payload = eth['payload']
        
        # IPv4
        if eth['ethertype'] == 0x0800:
            ip = parse_ip_header(payload)
            result['layers'].append(('ipv4', ip))
            
            # TCP
            if ip['protocol'] == 6:
                tcp = parse_tcp_header(ip['payload'])
                result['layers'].append(('tcp', tcp))
            # UDP
            elif ip['protocol'] == 17:
                udp = parse_udp_header(ip['payload'])
                result['layers'].append(('udp', udp))
    except PacketParseError:
        pass
    
    return result


def fuzz_target(data: bytes) -> None:
    if len(data) == 0:
        return
    
    try:
        _ = process_packet(data)
    except PacketParseError:
        pass
    except struct.error:
        pass
    except RecursionError:
        pass
    except MemoryError:
        pass


if __name__ == '__main__':
    try:
        import atheris
        atheris.Setup(sys.argv, lambda d: fuzz_target(d))
        atheris.Fuzz()
    except ImportError:
        print("atheris not installed")