from util import *
from TLS_protocol import ClientHello
cbc_cipher = 'c014c00ac022c021c020009100390038003700360088008700860085c019003a0089c00fc0050035c03600840095008dc013c009c01fc01ec01d0033003200310030009a0099009800970045004400430042c0180034009b0046c00ec004002fc03500900096004100070094008c00210025c012c008c01cc01bc01a001600130010000dc017001bc00dc003000a0093008b001f0023c034008f006300150012000f000c001a00620009001e00220014001100190008000600270026002a0029000b000e'

# check cbc cipher for SSLv3, TLSv1.0
class BeastTest(Test) :
    def start(self) :
        version = getHighestTLSVersion(self._result)
        
        vuln = 0 # Not vulnerable
        for version in [0,1] :
            if isTLSVersionSupport(self._result, version) :
                hello = ClientHello()
                hello.ciphersuite = cbc_cipher
                hello.version = version
                hello = addNecessaryExtensionToHelloObject(hello, self._host)
                if tryHandshake(self._host, self._port, hello.createAsHex()) == version :
                    # Vulnerable
                    print("[BEAST] Vulnerable, handshake success with version %d" % version)
                    vuln = 1
        
        if getHighestTLSVersion(self._result) <= 1 and vuln == 1 :
            vuln = 2 # TLS1.0 is highest protocol

        self._result.addResult('beast', vuln)
        if vuln == 2 :
            self._result.addVulnerability('beast')
            for cipherHex in splitCipherHexStringTLS(cbc_cipher) :
                for supportedVersion in getSupportedTLSVersion(self._result) :
                    if supportedVersion > 1 : 
                        continue
                    self._result.addVulnerabilityToCipher(cipherHex, versionIntToString(supportedVersion), '<b style="color:orange;">BEAST</b>')