import socket
from TLS_protocol import *

def sendData(host, port, data) : # Send data and get a reply (usually used for sending client hello and receive server hello)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
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
        pass
    return -1 # Handshake failure

def isTLSVersionSupport(result, ver) : # Check if SSL/TLS version is supported (ver = 0, 1, 2, 3)
    return result.getResult(['offer_ssl3','offer_tls10','offer_tls11','offer_tls12'][ver])

def getHighestTLSVersion(result) : # Get highest TLS version that the server supported
    for ver in [3,2,1,0] :
        if isTLSVersionSupport(result, ver) :
            return ver
    return -1

def getSupportedTLSVersion(result) : # Get a list of supported TLS version
    return list(filter(lambda x : isTLSVersionSupport(result,x), range(4)))

def versionIntToString(version) : # 0,1,2,3 =====> SSLv3.0 / TLSv1.0 / TLSv1.1 / TLSv1.2
    return '%sv%s' % ('SSL' if version==0 else 'TLS', '3.0' if version == 0 else ('1.%d' % (version-1)))

def getSupportedCipher(host, port, version, ciphers) : # ciphers is array of ciphers in hex
    toRet = []
    while True :
        if len(ciphers) == 0 :
            break
        hello = ClientHello()
        hello.ciphersuite = ''.join(ciphers)
        hello.version = version
        hello = addNecessaryExtensionToHelloObject(hello, host)

        serverHello = getServerHelloObject(host, port, hello.createAsHex())
        if serverHello != None and serverHello.version == version : # OK, get negotiated cipher
            toRet.append(serverHello.ciphersuite)
            ciphers.remove(serverHello.ciphersuite)
        else :
            break
    return toRet

def splitCipherHexStringTLS(cipherHexString) : # Split into each cipher
    toRet = []
    for i in range(0,len(cipherHexString),4) :
        toRet.append(cipherHexString[i:i+4])
    return toRet

def splitCipherHexStringSSL2(cipherHexString) : # Split into each cipher
    toRet = []
    for i in range(0,len(cipherHexString),6) :
        toRet.append(cipherHexString[i:i+6])
    return toRet

# cbc_hello = '16030100eb010000e7[0303]54511e7adeadbeef3133070000000000cfbd3904cc160a8503909f770433d4de00002ec012c008c01cc01bc01a001600130010000dc017001bc00dc003000a0093008b001f0023c034008ffeffffe000ff0100009000000013001100000e7777772e676f6f676c652e636f6d0023000033740000000d0020001e060106020603050105020503040104020403030103020303020102020203000a003e003c000e000d0019001c001e000b000c001b00180009000a001a00160017001d000800060007001400150004000500120013000100020003000f00100011000b00020100000f000101'
#              012345678901234567 8901 2
def modifyHelloVersion(hello, targetVer) : # Edit client hello (in hex) TLS verison
    return hello[:18] + '030' + str(targetVer) + hello[22:]


def getServerHelloObject(host, port, hello) : # Send client hello (in hex) and receive server hello object
    try :
        data = sendData(host, port, hello.decode('hex'))
        return ServerHello(data.encode('hex'))
    except BaseException as e :
        pass
    return None # Handshake failure


def addNecessaryExtensionToHelloObject(helloObj, hostname) :
    # SNI
    helloObj.addExtension(ServerNameIndication(hostname)) 
    # SessionTicketTLS
    helloObj.addExtension(SessionTicketTLS())
    # Signature algorithms
    helloObj.addExtension(GenericExtension('000d0020001e060106020603050105020503040104020403030103020303020102020203')) 
    # SupportedGroup
    helloObj.addExtension(GenericExtension('000a003e003c000e000d0019001c001e000b000c001b00180009000a001a00160017001d000800060007001400150004000500120013000100020003000f00100011'))
    # EC_Point format (Not important)
    #hel.addExtension(GenericExtension('000b00020100')) 
    # Heartbeat
    helloObj.addExtension(GenericExtension('000f000101'))
    return helloObj

def addNecessaryExtensionToHello(hello, hostname) :
    hel = ClientHello()
    hel.parseFromHex(hello)
    addNecessaryExtensionToHelloObject(hel, hostname)
    return hel.createAsHex()


class Test : # Every test should extend this
    def __init__(self, result, host, port, scan_speed='normal', scan_accuracy='normal') :
        self._result = result
        self._host = host
        self._port = port
        
        self.scan_speed = scan_speed # scan speed: fast, normal, thorough
        self.scan_accuracy = scan_accuracy # scan accuracy: minimise_false_negatives, normal, minimise_false_positives
        self.init()

    def init(self) :
        pass # Implement your init procedure here (For example: Loading file)

    def start(self) :
        pass # Implement your testing procedure here

'''
# Unused and unfinished functon, could be useful later (See code in LOGJAM for an almost completed version of this)
def doFullHandshake(host, port, version, hello) :
    # do a full handshake instead of hello (parse all response from server)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try :
        s.connect((host, port))
        s.sendall(hello.decode('hex'))
        while True :
            # Loop until receive ServerHelloDone
        rec = s.recv(1024*10)
        s.close()
    except BaseException as e :
        s.close()
        raise e
    return rec
'''