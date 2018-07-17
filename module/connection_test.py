import socket
import os
from util import *

# SSLv2 spec
# 0x80
# LENGTH [1]
# 0x01 = HELLO
# 0x00 0x02 = SSL 2.0
# CIPHER SPEC LENGTH (CIPHER * 3) [2]
# Session ID Length [2] - IGNORED
# Challenge Length [2]
# <FOREACH CIPHER SPEC>
#   Cipher spec [3]
# Challenge / Session ID

sslv2_hello = "803e0100020015001000100100800200800600400400800700c00800800500806161616161616161616161616161616161616161616161616161616161616161"
def test_sslv2(host, port) :
    try :
        data = sendData(host, port, sslv2_hello.decode('hex'))
        # If received alert (protocol_version 0x46 = 70) [15][0304][0002][02][46]
        if ord(data[0]) == 21 and ord(data[6]) == 70 :
            return False

        if len(data) >= 3 and ord(data[2]) == 4 :
            # Received Server hello
            return True
    except :
        pass
    return False

# SSLv3 spec
# 0x16 Handshake
# 0x03 0x00 SSL v3.0
# LENGTH [2]
#   0x01 Client hello
#   LENGTH [3]
#   0x03 0x00 SSL v3.0
#   RANDOM [32]
#       UNIX TIME [4]
#       RANDOM [28]
#   SESSION ID LENGTH [1]
#   CIPHER SUITE LENGTH (CIPHER*2) [2]
#   <FOREACH CIPHER SUITE>
#       CIPHER SUITE [2]
#   COMPRESSION LENGTH [1]
#   <FOREACH COMPRESSION>
#       COMPRESSION [1]     -> null = 0

sslv3_hello = "160300009a0100009603001e8b85b1d11074f011e217aa486aef746511d0ac1320c9552e9d33bceaba64c500006ec014c00a00390038003700360088008700860085c00fc005003500840095c013c0090033003200310030009a0099009800970045004400430042c00ec004002f0096004100070094c011c0070066c00cc002000500040092c012c008001600130010000dc00dc003000a009300ff020100"
def test_sslv3(host, port) :
    return tryHandshake(host, port, addNecessaryExtensionToHello(sslv3_hello, host)) == 0


tls10_hello = "16030100eb010000e703011e35618ca5aca589bb1b2e2e085a43613fcbdc199208fa5cb0499c793fa3d60100006ec014c00a00390038003700360088008700860085c00fc005003500840095c013c0090033003200310030009a0099009800970045004400430042c00ec004002f0096004100070094c011c0070066c00cc002000500040092c012c008001600130010000dc00dc003000a009300ff020100004f000b000403000102000a003a0038000e000d0019001c000b000c001b00180009000a001a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101"
def test_tls10(host, port) :
    return tryHandshake(host, port, addNecessaryExtensionToHello(tls10_hello, host)) == 1


tls11_hello = "16030100eb010000e70302e8f61847df51d3dc09d1409805aafa42ee03ae41247f67788cae75ef4c917daa00006ec014c00a00390038003700360088008700860085c00fc005003500840095c013c0090033003200310030009a0099009800970045004400430042c00ec004002f0096004100070094c011c0070066c00cc002000500040092c012c008001600130010000dc00dc003000a009300ff020100004f000b000403000102000a003a0038000e000d0019001c000b000c001b00180009000a001a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101"
def test_tls11(host, port) :
    return tryHandshake(host, port, addNecessaryExtensionToHello(tls11_hello, host)) == 2


tls12_hello = "16030100eb010000e70303e8f61847df51d3dc09d1409805aafa42ee03ae41247f67788cae75ef4c917daa00006ec014c00a00390038003700360088008700860085c00fc005003500840095c013c0090033003200310030009a0099009800970045004400430042c00ec004002f0096004100070094c011c0070066c00cc002000500040092c012c008001600130010000dc00dc003000a009300ff020100004f000b000403000102000a003a0038000e000d0019001c000b000c001b00180009000a001a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101"
def test_tls12(host, port) :
     return tryHandshake(host, port, addNecessaryExtensionToHello(tls12_hello, host)) == 3


class ConnectionTest(Test) :
    def start(self) :
        self._result.addResult('offer_ssl2',test_sslv2(self._host,self._port))
        if self._result.getResult('offer_ssl2') :
            self._result.addVulnerability('offer_ssl2')

        self._result.addResult('offer_ssl3',test_sslv3(self._host,self._port))
        if self._result.getResult('offer_ssl3') :
            self._result.addVulnerability('offer_ssl3')
            
        self._result.addResult('offer_tls10',test_tls10(self._host,self._port))
        self._result.addResult('offer_tls11',test_tls11(self._host,self._port))
        self._result.addResult('offer_tls12',test_tls12(self._host,self._port))

        if all([not self._result.getResult(proto) for proto in ['offer_ssl2','offer_ssl3','offer_tls10','offer_tls11','offer_tls12']]) :
            print("[Connection] Server does not support any offered protocols (SSLv2 to TLS1.2)")
            self._result.addResult('connectable',False)
        else :
            self._result.addResult('connectable',True)
