from util import *
from TLS_protocol import ClientHello
cbc_cipher1 = 'c028c024c014c00ac022c021c02000b700b30091c09bc099c09700afc095006b006a006900680039003800370036c077c07300c400c300c200c10088008700860085c019006d003a00c50089c02ac026c00fc005c079c075003d003500c0c038c03600840095008dc03dc03fc041c043c045c047c049c04bc04dc04fc065c067c069c071c027c023c013c009c01fc01ec01d00670040003f003e0033003200310030c076c07200be00bd00bc00bb009a0099009800970045004400430042c018006c003400bf009b0046c029c025c00ec004c078c074003c002f00ba'
cbc_cipher2 = 'c037c03500b600b2009000960041c09ac098c09600aec09400070094008c00210025c03cc03ec040c042c044c046c048c04ac04cc04ec064c066c068c070c012c008c01cc01bc01a001600130010000dc017001bc00dc003000a0093008b001f0023c034008ffeffffe0006300150012000f000c001a006200090061001e0022fefeffe10014001100190008000600270026002a0029000b000e'

class Lucky13Test(Test) :
    def start(self) :
        version = getHighestTLSVersion(self._result)
        if version == -1 :
            print("[LUCKY13] No valid TLS version found")
            self._result.addResult('lucky13', False)
            return
        print("Testing LUCKY13 with TLS version ",version)

        hello1 = ClientHello()
        hello1.ciphersuite = cbc_cipher1
        hello1hex = hello1.createAsHex()


        hello2 = ClientHello()
        hello2.ciphersuite = cbc_cipher2
        hello2hex = hello2.createAsHex()

        self._result.addResult('lucky13',tryHandshake(self._host, self._port, addNecessaryExtensionToHello(modifyHelloVersion(hello1hex,version), self._host)) >= 0 or tryHandshake(self._host, self._port, addNecessaryExtensionToHello(modifyHelloVersion(hello2hex,version), self._host)) >= 0)
        if self._result.getResult('lucky13') and self.scan_accuracy != 'minimise_false_negatives' :
            self._result.addVulnerability('lucky13')
            # for each cipher
            for cipherHex in splitCipherHexStringTLS(cbc_cipher1)+splitCipherHexStringTLS(cbc_cipher2) :
                for supportedVersion in getSupportedTLSVersion(self._result) :
                    self._result.addVulnerabilityToCipher(cipherHex, versionIntToString(supportedVersion), '<b style="color:orange;">LUCKY13</b>')