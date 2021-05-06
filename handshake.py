#!/usr/bin/python3
'''
Usage: python3 handshake.py <IPADDRESS> <PORT>
'''
import struct
import gevent.socket
import sys
import cbor2
import time

network_magic = 764824073
PROTOCOL_VERSION = 2

def pack_u32(n):
    return struct.pack('>I', n)

def unpack_u32(s):
    return struct.unpack('>I', s)[0]

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def unpack_u32(s):
    return struct.unpack('>I', s)[0]

def endpoint_connect(host, port):
    print('Opening a TCP connection to %s:%d' % (host, port))
    # Open a socket
    sock = gevent.socket.create_connection((host, port))
    return sock

def handshake(sock):
    start_time = time.time()
    # Create the object for verison proposal
    obj = [0, {1 : network_magic, 2: network_magic, 3: network_magic, 4: [network_magic, False], 5: [network_magic, False], 6: [network_magic, False]}]
    # Object as CBOR
    cbor_obj = cbor2.dumps(obj)
    # Time in milliseconds
    time_since_start = round(time.time()*1000 - start_time*1000)
    cbor_time = struct.pack('>I', time_since_start)
    # Protocol version 
    protocol = struct.pack('>I', PROTOCOL_VERSION)
    # Length of payload
    length = struct.pack('>I', len(cbor_obj))
    msg = protocol + length + cbor_obj
    print('-----------')
    print('Protocol Version: ' + protocol.hex())
    print('Length: ' + length.hex())
    print('Available Options: ' + cbor2.dumps(cbor_obj).hex())
    print('-----------')
    print('Constructed Payload: ' + msg.hex())
    print('-----------\n')
    sock.sendall(msg)
    # STATE: PROPOSE
    resp = recvall(sock, 18)
    print('Node hex Response: ' + resp.hex())
    # Last 10 bytes are the version selected
    result = cbor2.loads(resp[8:])
    print('Version Selection: ' + str(result), (resp[8:].hex()))
    return sock 

def main():
    host, port = sys.argv[1], int(sys.argv[2])
    sock = endpoint_connect(host, port)
    handshake(sock)
    return

if __name__ == '__main__':
    main()
