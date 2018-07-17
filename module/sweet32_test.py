
from util import *

cipherHexFull = 'c012c008c01cc01bc01a001600130010000dc017001bc00dc003000a0093008b001f0023c034008ffeffffe0'

sweet32_hello = '16030100d4010000d0030354511e7adeadbeef3133070000000000cfbd3904cc160a8503909f770433d4de00002ec012c008c01cc01bc01a001600130010000dc017001bc00dc003000a0093008b001f0023c034008ffeffffe000ff010000790023000033740000000d0020001e060106020603050105020503040104020403030103020303020102020203000a003e003c000e000d0019001c001e000b000c001b00180009000a001a00160017001d000800060007001400150004000500120013000100020003000f00100011000b00020100000f000101'
class Sweet32Test(Test) :
    def start(self) :
        version = getHighestTLSVersion(self._result)
        if version == -1 :
            print("[Sweet32] No valid TLS version found")
            self._result.addResult('sweet32', False)
            return
        print("[Sweet32] Testing with TLS version ",version)
        self._result.addResult('sweet32',tryHandshake(self._host, self._port, addNecessaryExtensionToHello(modifyHelloVersion(sweet32_hello,version), self._host)) != -1)
        if self._result.getResult('sweet32') :
            self._result.addVulnerability('sweet32')

            for version in getSupportedTLSVersion(self._result) :
                for cipherHex in splitCipherHexStringTLS(cipherHexFull) :
                    self._result.addVulnerabilityToCipher(cipherHex, versionIntToString(version), '<b style="color:orange;">SWEET32</b>')