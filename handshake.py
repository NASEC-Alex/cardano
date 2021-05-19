#!/usr/bin/python3
'''
Usage: python3 handshake.py <IPADDRESS> <PORT>
'''
import struct
import sys
import cbor2
import time
import logging
import socket
import bitstring

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
network_magic = 764824073

def pack_u32(n):
    return struct.pack('>I', n)


def unpack_u32(s):
    return struct.unpack('>I', s)[0]


def recv_data(sock, n):
    # Helper function to recv n bytes where n should be the header['length'] or 8 to parse headers
    data = sock.recv(n)
    return data


def node_response(sock):
    # Receive next packet
    resp = recv_data(sock, 8)
    headers = parse_headers(resp)
    logging.debug(headers)
    data = recv_data(sock, headers['length'])
    return cbor2.loads(data)


def endpoint_connect(host, port):
    logging.info('Opening a TCP connection to %s:%d' % (host, port))
    # Open a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


def convert_bits(data):
    '''
    Used to convert bytes to bits for deconstructing headers
    '''
    bits = ''
    for my_byte in data:
        bits += f'{my_byte:0>8b}'
    return bits


def parse_headers(resp):
    '''
    Parse protocol headers to retrieve 
    - Timestamp: Bytes 0 to 3
    - Mode & Mini Protocol Version: Bytes 4 and 5, first bit (Mode) & 15 bit remainder (Version) 
    - Length: Bytes 6 and 7
    '''
    headers = dict()
    # Obtain Mode and Mini Protocol Version
    mode_mini_protcol = convert_bits(resp[4 : 6])
    # Build headers dictionary
    headers['length'] = int(resp[6 :].hex(), 16)
    headers['timestamp'] = str(unpack_u32(resp[:4]))[:4] + '.' + str(unpack_u32(resp[:4]))[4:]
    headers['mode'] = mode_mini_protcol[0]
    headers['mini_protocol'] = int(mode_mini_protcol[1:], 2)
    return headers


def mode_bit_manipulation(protocol_id, mode):
    protocol_two_byte_bits = convert_bits(protocol_id.to_bytes(2, 'big'))
    protocol_bitarray = bitstring.BitArray(bin=protocol_two_byte_bits)
    protocol_binary = protocol_bitarray.bin[1:]
    mode_binary = bitstring.BitArray(bin=str(mode)).bin
    mode_mini_protocol_binary = bitstring.BitArray(bin=mode_binary + protocol_binary)
    return mode_mini_protocol_binary.tobytes()


def build_headers(protocol_id, payload, mode=0):
    '''
    Create the object for verison proposal
    Time: Monotonic time that increments constantly
    Mode: 1 or 0, the first bit of the 2 protocol ID bytes
    Protocol ID: last 15 bits of the protocol ID bytes
    Length: last two bytes of header representing the length of the payload
    '''
    header = dict()
    header['time'] = struct.pack('>I', int(time.monotonic() * 1000))
    header['mode'] = mode # unused but available for reference
    header['protocol_id'] = str(convert_bits(protocol_id.to_bytes(2, 'big')))[:15] # unusued but available for reference
    header['mode_mini_protocol_id'] = mode_bit_manipulation(protocol_id, mode)
    header['length'] = len(payload).to_bytes(2, 'big')
    logging.debug(header)
    logging.debug('Request Time Binary: ' + convert_bits(header['time']))
    logging.debug('Request Mode Binary: ' + convert_bits(header['mode_mini_protocol_id']))
    logging.debug('Length: ' + convert_bits(header['length']))
    return header


def handshake(sock):
    '''
    Handshake with the Cardano Node
    '''
    # You can propose all of the versions
    # obj = [0, {1 : network_magic, 2: network_magic, 3: network_magic, 4: [network_magic, False], 5: [network_magic, False], 6: [network_magic, False], 7: [network_magic, False]}]
    obj = [0, {4: [network_magic, False]}]
    # Object as CBOR
    cbor_obj = cbor2.dumps(obj)
    header = build_headers(0, cbor_obj)
    logging.debug('Full Request Header Binary: ' + convert_bits(header['time'] + header['mode_mini_protocol_id'] + header['length']))
    # Length of payload
    msg = header['time'] + header['mode_mini_protocol_id'] + header['length'] + cbor_obj
    logging.debug('Length: ' + str(len(cbor_obj)))
    logging.debug('Version Options: ' + str(obj) + ' ' + cbor2.dumps(cbor_obj).hex())
    logging.debug('Constructed Payload: ' + msg.hex())
    # STATE: PROPOSE
    logging.info('>>> Version Proposal: ' + str(cbor2.loads(cbor_obj)))
    sock.send(msg)
    data = node_response(sock)
    logging.info('<<< Version: ' + str(data))
    return


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    sock = endpoint_connect(host, port)
    handshake(sock)
    data = node_response(sock)
    logging.info('<<< ' + str(data))
    return


if __name__ == '__main__':
    main()
