import socket

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

def tryHandshake(host, port, hello) : # Handshake for SSLv3 - TLS 1.2
    try :
        data = sendData(host, port, hello.decode('hex'))
        if len(data)>5 and ord(data[0]) == 22 and ord(data[1]) == 3 and ord(data[5]) == 2 :
            return ord(data[2]) # Return handshake version
    except BaseException as e :
        print e
        pass
    return -1 # Handshake failure

def isTLSVersionSupport(result, ver) : # Check if SSL/TLS version is supported (ver = 0, 1, 2, 3)
    return result.getResult(['offer_ssl3','offer_tls10','offer_tls11','offer_tls12'][ver])

def getHighestTLSVersion(result) : # Get highest TLS version that the server supported
    for ver in [3,2,1,0] :
        if isTLSVersionSupport(result, ver) :
            return ver
    return -1


# cbc_hello = '16030100eb010000e7[0303]54511e7adeadbeef3133070000000000cfbd3904cc160a8503909f770433d4de00002ec012c008c01cc01bc01a001600130010000dc017001bc00dc003000a0093008b001f0023c034008ffeffffe000ff0100009000000013001100000e7777772e676f6f676c652e636f6d0023000033740000000d0020001e060106020603050105020503040104020403030103020303020102020203000a003e003c000e000d0019001c001e000b000c001b00180009000a001a00160017001d000800060007001400150004000500120013000100020003000f00100011000b00020100000f000101'
#              012345678901234567 8901 2
def modifyHelloVersion(hello, targetVer) :
    return hello[:18] + '030' + str(targetVer) + hello[22:]