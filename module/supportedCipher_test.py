from util import *
from TLS_protocol import ClientHello, intToHex
import copy

class SupportedCipherTest(Test) :
    def init(self) :
        self.supportedCipherSuites = {}
        self.supportedCipherSuites['SSLv2.0'] = []
        self.supportedCipherSuites['SSLv3.0'] = []
        self.supportedCipherSuites['TLSv1.0'] = []
        self.supportedCipherSuites['TLSv1.1'] = []
        self.supportedCipherSuites['TLSv1.2'] = []
    
    def testSSL2(self, cipher) :
        # No easy SSLv2 hello
        hello = '80'
        hello += intToHex(3 + 2 + 2 + 2 + len(cipher)//2 + 16 + 16,1)
        hello += '010002'
        hello += intToHex(len(cipher)//2,2)
        hello += '0010' # Session = 16
        hello += '0010' # Challenge = 16
        hello += cipher
        hello += '61616161616161616161616161616161'
        hello += '61616161616161616161616161616161'
 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try :
            s.connect((self._host, self._port))
            s.sendall(hello.decode('hex'))
            recvBuffer = ''
            while True :
                rec = s.recv(1024*10)
                if rec == None : break
                recvBuffer += rec
                respLen = (ord(recvBuffer[0]) & 0b00111111)*256 + ord(recvBuffer[1])
                #print(len(recvBuffer), "expect", respLen)
                if len(recvBuffer) >= respLen :
                    # GO
                    s.close()
                    certLen = int(recvBuffer[7:9].encode('hex'), 16)
                    cipherLen = int(recvBuffer[9:11].encode('hex'), 16)
                    cipherList = recvBuffer[13 + certLen : 13 + certLen + cipherLen].encode('hex')
                    for cipherHex in splitCipherHexStringSSL2(cipherList) :
                        if cipherHex == cipher :
                            return True
                    return False
        except BaseException as e :
            print(e)
            s.close()
            pass
        return False

    def testTLS(self, cipher, version) :
        # Easy
        hello = ClientHello()
        hello.ciphersuite = cipher
        hello.version = version
        return tryHandshake(self._host, self._port, addNecessaryExtensionToHelloObject(hello, self._host).createAsHex()) == version

    def start(self) :
        # Parse cipherlist from ../data/cipher-mapping.txt
        data = open("data/cipher-mapping.txt", "r")
        ciphers_ssl2 = []
        ciphers_tls = []
        ciphers_dict = {} # Map from byte -> cipher data
        for line in data :
            x = line.split()
            byte = x[0]
            name_openssl = x[2]
            name_rfc = x[3]
            cipher = {
                'byte' : ''.join([i[2:] for i in byte.split(',')]).lower(),
                'name_ossl' : name_openssl,
                'name_rfc' : name_rfc,
                'name' : name_openssl if name_openssl != '-' else name_rfc,
                'vulnerabilities': []
            }

            if len(cipher['byte']) == 6 :
                ciphers_ssl2.append(cipher)
            else :
                ciphers_tls.append(cipher)

            ciphers_dict[cipher['byte']] = cipher

        data.close()

        print("Loaded %d SSLv2 and %d TLS ciphers" % (len(ciphers_ssl2), len(ciphers_tls)))

        # test sslv2
        if self._result.getResult('offer_ssl2') :
            toRet = "SSLv2:\n"
            for cipher in ciphers_ssl2 :
                if self.testSSL2(cipher['byte']) :
                    toRet += '    '+cipher['name'] + '\n'
                    self.supportedCipherSuites['SSLv2.0'].append(copy.deepcopy(cipher))
            #print(toRet)
        # test for each tls version
        for version in getSupportedTLSVersion(self._result) :
            toRet = "%s:\n" % versionIntToString(version)
            # split into bundle of 100 ciphers
            for i in range(0, len(ciphers_tls), 100) :
                ciphers = [x['byte'] for x in ciphers_tls[i:i+100]]
                # test
                supportedCipher = getSupportedCipher(self._host, self._port, version, ciphers)
                for cipher in supportedCipher :
                    toRet += '    '+ciphers_dict[cipher]['name'] + '\n'
                    self.supportedCipherSuites[versionIntToString(version)].append(copy.deepcopy(ciphers_dict[cipher]))
            #print(toRet)
        
        self._result.addResult('supported_ciphers', self.supportedCipherSuites)