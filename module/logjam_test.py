# Cipher list obtained from testssl.sh
dh_export = '0063006500140011'
all_dh_ciphers = "cc1500b30091c09700a3009fccaac0a3c09f006b006a0039003800c400c30088008700a7006d003a00c5008900abccadc0a7c043c045c047c053c057c05bc067c06dc07dc081c085c09100a2009ec0a2c09e00aac0a6006700400033003200be00bd009a00990045004400a6006c003400bf009b004600b20090c096c042c044c046c052c056c05ac066c06cc07cc080c084c09000660018008e00160013001b008f006300150012001a0065001400110019001700b500b4002d"

from util import *
from TLS_protocol import ClientHello, intToHex
import socket

class LogjamTest(Test) :
    def init(self) :
        # load common prime
        self.commonPrime = {}
        commonPrimeFile = open("data/common-primes.txt","r")
        data = [x.strip() for x in commonPrimeFile.readlines()]
        commonPrimeFile.close()
        for line in range(len(data)) :
            if data[line][0:2] == '# ' :
                # next line is prime
                prime = data[line+1].lower()
                self.commonPrime[prime] = data[line][2:].replace('"','')



    def startExport(self) :
        vuln = False
        for version in getSupportedTLSVersion(self._result) :
            # Try handshake with dh_export cipher
            hello = ClientHello()
            hello.ciphersuite = dh_export
            hello.version = version
            hello = addNecessaryExtensionToHelloObject(hello, self._host)
            if tryHandshake(self._host, self._port, hello.createAsHex()) == version :
                # vulnerable,
                vuln = True
                for cipherHex in splitCipherHexStringTLS(dh_export) :
                    self._result.addVulnerabilityToCipher(cipherHex, versionIntToString(version), '<b style="color:red;">LOGJAM</b>')
        
        self._result.addResult('logjam_export', vuln)
        if vuln :
            self._result.addVulnerability('logjam_export')
    
    def startCommonPrime(self) :

        def testForVersion(version) :
            hello = ClientHello()
            hello.ciphersuite = all_dh_ciphers
            hello.version = version
            hello = addNecessaryExtensionToHelloObject(hello, self._host)
            # do full handshake until received key exchange
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            vuln = False
            try :
                s.connect((self._host, self._port))
                s.sendall(hello.createAsHex().decode('hex'))
                recvBuffer = ''
                while True :
                    rec = s.recv(1024*10)
                    if rec == None : break
                    recvBuffer += rec
                    # Check for TLS Record
                    breakConnection = False
                    while len(recvBuffer) >= 5 :
                        if ord(recvBuffer[0]) == 0x15 :
                            # Alert ...
                            #print("[LOGJAM] Received some ALERT")
                            breakConnection = True
                        elif ord(recvBuffer[0]) == 0x16 :
                            # Handshake message
                            recvVersion = ord(recvBuffer[2])
                            messageLen = ord(recvBuffer[3])*256 + ord(recvBuffer[4])
                            # Check if enough message to consume
                            #print("[LOGJAM] Buffer %d, Expected message length %d" % (len(recvBuffer),messageLen))
                            if len(recvBuffer) >= 5 + messageLen :
                                # consume !
                                #print("[LOGJAM] Consuming handshake message")
                                recordHeader, messageBuffer, recvBuffer = recvBuffer[0:5], recvBuffer[5:5+messageLen], recvBuffer[5+messageLen:]
                                while len(messageBuffer)>=6 :
                                    #print("[LOGJAM] Message Buffer %d" % len(messageBuffer))
                                    msgLen = int(messageBuffer[1:4].encode('hex'), 16) + 4 # ([P][LEN]<msgLen>)
                                    #print("[LOGJAM] Message length %d" % msgLen)
                                    handshakeMessage, messageBuffer = messageBuffer[0:msgLen], messageBuffer[msgLen:]
                                    # Check protocol
                                    if ord(handshakeMessage[0]) == 0x0c :
                                        print("[LOGJAM] Received KeyExchange")
                                        # Key exchange protocol
                                        msgLen = int(handshakeMessage[1:4].encode('hex'), 16)
                                        pLen = int(handshakeMessage[4:6].encode('hex'),16)
                                        p = handshakeMessage[6:6 + pLen].encode('hex')

                                        print("prime : %s" % p)
                                        # Check with common prime list
                                        if p in self.commonPrime :
                                            print("[LOGJAM] Found common prime : %s (%d-bit)" % (self.commonPrime[p], len(p)*4))
                                            if len(p)*4 <= 1024 :
                                                vuln = True

                                        else :
                                            print("[LOGJAM] Common prime not found")
                                        breakConnection = True
                                    elif ord(handshakeMessage[0]) == 0x0e :
                                        print("[LOGJAM] Received ServerHelloDone")
                                        breakConnection = True
                                    elif ord(handshakeMessage[0]) == 0x0b :
                                        print("[LOGJAM] Received Certificate")
                                        pass
                                    elif ord(handshakeMessage[0]) == 0x02 :
                                        pass
                                        print("[LOGJAM] Received ServerHello")
                                    else :
                                        print("[LOGJAM] Received protocol %d" % ord(handshakeMessage[0]))
                            else :
                                # Need more data
                                break
                        else :
                            print("[LOGJAM] Received unknown record %d " % ord(recvBuffer[0]))
                            breakConnection = True
                        if breakConnection : break
                    if breakConnection : break
            except socket.timeout as e :
                print("[LOGJAM] Socket timeout")
            except socket.error as e :
                print("[LOGJAM] Socket error")
            except BaseException as e :
                print("[LOGJAM] Error:",e)
            finally :
                s.close()
            return vuln


        vuln = False
        for version in getSupportedTLSVersion(self._result) :
            if testForVersion(version) :
                vuln = True

        
        self._result.addResult('logjam_common', vuln)
        if vuln :
            self._result.addVulnerability('logjam_common')
        
    def start(self) :
        self.startExport()
        self.startCommonPrime()
