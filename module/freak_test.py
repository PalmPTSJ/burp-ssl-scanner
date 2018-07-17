
from util import *
import connection_test

freak_hello = '16030100920100008e030354511e7adeadbeef3133070000000000cfbd3904cc160a8503909f770433d4de00001400620061006400600014000e00080006000300ff010000510000001c001a00001773747564656e742e656e672e6368756c612e61632e74680023000033740000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101'
freak_hello_ssl2 = '801f0100020006000000100400800200802922beb35a018b04fe5f8003a013ebc4'


class FreakTest(Test) :
    def start(self) :
        # For every version
        vuln = False
        for ver in range(4) :
            if isTLSVersionSupport(self._result, ver) :
                if tryHandshake(self._host, self._port, addNecessaryExtensionToHello(modifyHelloVersion(freak_hello, ver), self._host)) != -1 :
                    print("[FREAK] Handshake success with version ",ver)
                    vuln = True

                    for cipherHex in splitCipherHexStringTLS('00620061006400600014000e000800060003') :
                        self._result.addVulnerabilityToCipher(cipherHex, versionIntToString(ver), '<b style="color:red;">FREAK</b>')
        if self._result.getResult('offer_ssl2') :
            # Try ssl2
            # TODO: Test if this is working
            try :
                #data = connection_test.sendData(self._host, self._port, freak_hello_ssl2.decode('hex'))
                ssl2cipherList = self._result.getResult('supported_ciphers')['SSLv2.0']
                for cipher in ssl2cipherList :
                    if cipher['byte'] == '040080' or cipher['byte'] == '020080' :
                        print("[FREAK] SSLv2 server cipher vulnerable: %s" % cipher['name'])
                        vuln = True
                        self._result.addVulnerabilityToCipher(cipher['byte'], 'SSLv2.0', '<b style="color:red;">FREAK</b>')
            except :
                print("[FREAK] Something wrong with SSLv2 connection")
        
        self._result.addResult('freak', vuln)

        if(vuln) :
            self._result.addVulnerability('freak')