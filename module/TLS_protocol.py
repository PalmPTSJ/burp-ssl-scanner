def intToHex(n, b) :
    # n -> Hex of b bytes
    return ('0'*(b*2) + hex(n)[2:])[-(b*2):]

def consume(oriMsg, b) :
    # Consume b bytes from original message and return [Consumed, Leftover]
    return [oriMsg[:2*b], oriMsg[2*b:]]

class ClientHello :
    def __init__(self) :
        self.version = 3
        self.random = '54511e7adeadbeef3133070000000000cfbd3904cc160a8503909f770433d4de'
        self.ciphersuite = 'c014c00ac022c021c02000390038003700360088008700860085c00fc00500350084c013c009c01fc01ec01d00330032008000810082008300310030009a0099009800970045004400430042c00ec004002f009600410007c011c0070066c00cc00200050004c012c008c01cc01bc01a001600130010000dc00dc003000a006300150012000f000c006200090065006400140011000e000b00080006000300ff'
        self.compression = '00'
        self.extension = []

    def __createHelloAsHex(self) :
        toRet = '01' # Client Hello
        helloMsg = self.__createHelloMessageAsHex()
        toRet += intToHex(len(helloMsg)//2, 3)
        toRet += helloMsg
        return toRet

    def __createHelloMessageAsHex(self) :
        toRet = '030' + str(self.version) # TLS version
        toRet += self.random
        toRet += '00' # Session ID Length = 0
        toRet += intToHex(len(self.ciphersuite)//2, 2) # Ciphersuite length (2 bytes)
        toRet += self.ciphersuite
        toRet += intToHex(len(self.compression)//2, 1) # Compression length (1 byte)
        toRet += self.compression

        if len(self.extension) > 0 :
            # build extension
            toRet += self.__createExtensionListAsHex()

        return toRet

    def __createExtensionListAsHex(self) :
        extensionListHex = ''
        for ext in self.extension :
            extensionListHex += ext.createExtensionAsHex()
        
        return intToHex(len(extensionListHex)//2, 2) + extensionListHex

    def createAsHex(self) :
        # build ClientHello message
        toRet  = '16' # Handshake 0x16 = 22
        toRet += '0301' # TLS Version 1.0 (Record Layer protocol)
        hello = self.__createHelloAsHex()
        toRet += intToHex(len(hello)//2, 2)
        toRet += hello
        return toRet

    def addExtension(self, ext) :
        self.extension.append(ext)

    def parseFromHex(self, msg) :
        # Parse from existing message
        try :
            x, msg = consume(msg, 3) # 160301
            msg_len, msg = consume(msg, 2)

            # Hello Message
            x, msg = consume(msg, 1) # 01 = Client Hello
            hello_len, msg = consume(msg, 3)

            # Hello
            tlsVersion, msg = consume(msg, 2)
            self.version = int(tlsVersion[3],16)

            self.random, msg = consume(msg, 32)

            sess_len, msg = consume(msg, 1)
            sess_id, msg = consume(msg, int(sess_len,16))

            ciphersuite_len, msg = consume(msg, 2)
            self.ciphersuite, msg = consume(msg, int(ciphersuite_len, 16))

            compression_len, msg = consume(msg, 1)
            self.compression, msg = consume(msg, int(compression_len, 16))

            # Throw extension away (GG)

        except BaseException as e :
            print("Something went wrong while parsing hello ",e)


class ServerHello :
    def __init__(self, helloMsg) :
        self.version = 0
        self.random = ''
        self.sessionId = ''
        self.ciphersuite = ''
        self.compressionMethod = ''
        # helloMsg in hex
        if helloMsg != None :
            self.parseFromHex(helloMsg)
    
    def parseFromHex(self, msg) :
        x, msg = consume(msg, 3) # 160301
        msg_len, msg = consume(msg, 2)

        server_hello, msg = consume(msg, 1)
        if server_hello != '02' :
            raise BaseException('Not server hello message')

        hello_len, msg = consume(msg, 3)
        tlsVersion, msg = consume(msg, 2)
        self.version = int(tlsVersion[3],16)

        self.random, msg = consume(msg, 32)

        sess_len, msg = consume(msg, 1)
        self.sess_id, msg = consume(msg, int(sess_len,16))

        self.ciphersuite, msg = consume(msg, 2)
        self.compressionMethod, msg = consume(msg, 1)

        # ignore extension


class Extension :
    def __init__(self, extType) :
        self.type = extType
        self.message = ''
    
    def createExtensionAsHex(self) :
        toRet = self.type
        toRet += intToHex(len(self.message)//2, 2)
        toRet += self.message
        return toRet


class ServerNameIndication(Extension) :
    def __init__(self, hostname) :
        Extension.__init__(self, '0000')
        # create message
        self.message = intToHex(len(hostname)+3, 2)
        self.message += '00' # Type: host_name
        self.message += intToHex(len(hostname), 2)
        self.message += hostname.encode('hex')

class SessionTicketTLS(Extension) :
    def __init__(self) :
        Extension.__init__(self, '0023')

class NextProtoNeg(Extension) :
    def __init__(self) :
        Extension.__init__(self, '3374')

class GenericExtension(Extension) :
    def __init__(self, msg) :
        Extension.__init__(self, msg[:4])
        # Skip Length (2 bytes)
        self.message = msg[8:]



'''
class TLSRecordLayer() :

    TYPE_ALERT = '15' # 0x15
    TYPE_HANDSHAKE = '16' # 0x16

    def __init__(self, msg) :
        self.type = ''
        self.version = 0
        self.messageLen = 0
        self.message = None

        if msg != None :
            self.parseMessage(msg)

    def parseMessage(self, msg) :
        self.type, msg = consume(msg, 1)
        tls_version, msg = consume(msg, 2)
        self.version = int(tls_version[3], 16)



'''