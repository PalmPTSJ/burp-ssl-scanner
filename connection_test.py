import socket
import os

def sendData(host, port, data) :
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try :
        s.connect((host, port))
        
        s.sendall(data)
        rec = s.recv(1024*10)
        s.close()
    except BaseException as e :
        s.close()
        raise e
    return rec

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
# Challenge

sslv2_hello = "803e0100020015001000100100800200800600400400800700c00800800500806161616161616161616161616161616161616161616161616161616161616161"
def test_sslv2(host, port) :
    try :
        data = sendData(host, port, sslv2_hello.decode('hex'))
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
    try :
        data = sendData(host, port, sslv3_hello.decode('hex'))
        #print(data.encode('hex'))
        if len(data)>5 and ord(data[0]) == 22 and ord(data[5]) == 2 :
            # Received Handshake and Server Hello
            return True
    except :
        pass
    return False


tls10_hello = "16030100eb010000e703011e35618ca5aca589bb1b2e2e085a43613fcbdc199208fa5cb0499c793fa3d60100006ec014c00a00390038003700360088008700860085c00fc005003500840095c013c0090033003200310030009a0099009800970045004400430042c00ec004002f0096004100070094c011c0070066c00cc002000500040092c012c008001600130010000dc00dc003000a009300ff020100004f000b000403000102000a003a0038000e000d0019001c000b000c001b00180009000a001a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101"
def test_tls10(host, port) :
    try :
        data = sendData(host, port, tls10_hello.decode('hex'))
        #print(data.encode('hex'))
        if len(data)>5 and ord(data[0]) == 22 and ord(data[1]) == 3 and ord(data[2]) == 1 and ord(data[5]) == 2 :
            # Received Handshake with version 03 01 and Hello
            return True
    except :
        pass
    return False


tls11_hello = "16030100eb010000e70302e8f61847df51d3dc09d1409805aafa42ee03ae41247f67788cae75ef4c917daa00006ec014c00a00390038003700360088008700860085c00fc005003500840095c013c0090033003200310030009a0099009800970045004400430042c00ec004002f0096004100070094c011c0070066c00cc002000500040092c012c008001600130010000dc00dc003000a009300ff020100004f000b000403000102000a003a0038000e000d0019001c000b000c001b00180009000a001a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101"
def test_tls11(host, port) :
    try :
        data = sendData(host, port, tls11_hello.decode('hex'))
        #print(data.encode('hex'))
        if len(data)>5 and ord(data[0]) == 22 and ord(data[1]) == 3 and ord(data[2]) == 2 and ord(data[5]) == 2 :
            # Received Handshake with version 03 02 and Hello
            return True
    except :
        pass
    return False


#tls12_hello = "16030100cb010000c70303be31a08b927439f043a8b5e5ebf8eb7cd60d4d467428a8c940b6722ca3ed95c9000064c030c02cc028c024c014c00a00a500a300a1009f006b006a006900680039003800370036009d003d0035c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009c003c002fc012c008001600130010000d000a00ff0100003a000b000403000102000a000a00080019001800170013000d0020001e060106020603050105020503040104020403030103020303020102020203"
tls12_hello = "16030100eb010000e70303e8f61847df51d3dc09d1409805aafa42ee03ae41247f67788cae75ef4c917daa00006ec014c00a00390038003700360088008700860085c00fc005003500840095c013c0090033003200310030009a0099009800970045004400430042c00ec004002f0096004100070094c011c0070066c00cc002000500040092c012c008001600130010000dc00dc003000a009300ff020100004f000b000403000102000a003a0038000e000d0019001c000b000c001b00180009000a001a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101"

def test_tls12(host, port) :
    try :
        data = sendData(host, port, tls12_hello.decode('hex'))
        #print(data.encode('hex'))
        if len(data)>5 and ord(data[0]) == 22 and ord(data[1]) == 3 and ord(data[2]) == 3 and ord(data[5]) == 2 :
            # Received Handshake with version 03 03 and Hello
            return True
    except :
        pass
    return False

'''
if testModule() :
    print("Test passed")
else :
    print("Test failed")
'''
'''
80
3e
01
0002
0015
0010
0010
010080
020080
060040
040080
0700c0
080080
050080
61616161616161616161616161616161
61616161616161616161616161616161
'''