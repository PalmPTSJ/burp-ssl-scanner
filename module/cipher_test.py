# Cipher list obtained from testssl.sh
null_ciphers="c010c006c015c00bc001c03bc03ac03900b900b800b500b4002e002d00b100b0002c003b0002000100820083ff8700ff"
sslv2_null_ciphers=""
anon_ciphers="c01900a7006d003a00c50089c047c05bc085c01800a6006c003400bf009b0046c046c05ac084c0160018c017001b001a00190017c01500ff"
sslv2_anon_ciphers=""
adh_ciphers="00a7006d003a00c50089c047c05bc08500a6006c003400bf009b0046c046c05ac0840018001b001a0019001700ff"
sslv2_adh_ciphers=""
exp_ciphers="0063006200610065006400600014001100190008000600270026002a0029000b000e001700030028002b00ff"
sslv2_exp_ciphers="040080020080"
low_ciphers="00150012000f000c0009001e0022fefeffe100ff"
sslv2_low_ciphers="080080060040"
medium_ciphers="009a0099009800970096000700210025c011c0070066c00cc002000500040092008a00200024c033008e00ff"
sslv2_medium_ciphers="010080030080050080"
tdes_ciphers="c012c008c01cc01bc01a001600130010000dc00dc003000a0093008b001f0023c034008ffeffffe000ff"
sslv2_tdes_ciphers="0700c0"
high_ciphers="c028c024c014c00ac022c021c02000b700b30091c09bc099c09700afc095006b006a006900680039003800370036c077c07300c400c300c200c10088008700860085c02ac026c00fc005c079c075003d003500c0c038c03600840095008dc03dc03fc041c043c045c049c04bc04dc04fc065c067c069c07100800081ff00ff01ff02ff03ff85c027c023c013c009c01fc01ec01d00670040003f003e0033003200310030c076c07200be00bd00bc00bb0045004400430042c029c025c00ec004c078c074003c002f00bac037c03500b600b200900041c09ac098c09600aec0940094008cc03cc03ec040c042c044c048c04ac04cc04ec064c066c068c070"
strong_ciphers="13011302130313041305cc14cc13cc15c030c02c00a500a300a1009fcca9cca8ccaac0afc0adc0a3c09f00ad00abccaeccadccacc0abc0a7c032c02e009dc0a1c09d00a9ccabc0a9c0a5c051c053c055c057c059c05dc05fc061c063c06bc06dc06fc07bc07dc07fc081c083c087c089c08bc08dc08fc091c09316b716b816b916bac02fc02b00a400a200a0009ec0aec0acc0a2c09e00ac00aac0aac0a6c0a0c09c00a8c0a8c0a4c031c02d009cc050c052c054c056c058c05cc05ec060c062c06ac06cc06ec07ac07cc07ec080c082c086c088c08ac08cc08ec090c09200ff"

from util import *
from TLS_protocol import ClientHello, intToHex

testList = [
    # Name      CipherTLS       CipherSSLv2             Issue
    ['NULL',    null_ciphers,   sslv2_null_ciphers,     True ],
    ['ANON',    anon_ciphers,   sslv2_anon_ciphers,     True ],
    ['EXP',     exp_ciphers,    sslv2_exp_ciphers,      True ],
    ['LOW',     low_ciphers,    sslv2_low_ciphers,      True ],
    ['WEAK',    medium_ciphers, sslv2_medium_ciphers,   True ],
    ['3DES',    tdes_ciphers,   sslv2_tdes_ciphers,     True ],
    ['HIGH',    high_ciphers,   None,                   False],
    ['STRONG',  strong_ciphers, None,                   False]
]

class CipherTest(Test) :
    def testSSL2(self, cipher) :
        # No easy SSLv2 hello
        ssl2cipherList = self._result.getResult('supported_ciphers')['SSLv2.0']
        for supportedCipher in ssl2cipherList :
            for testingCipher in splitCipherHexStringSSL2(cipher) :
                if supportedCipher['byte'] == testingCipher :
                    return True
        return False
        

    def testTLS(self, cipher, version) :
        # Easy
        hello = ClientHello()
        hello.ciphersuite = cipher
        hello.version = version
        return tryHandshake(self._host, self._port, addNecessaryExtensionToHelloObject(hello, self._host).createAsHex()) == version

    def start(self) :
        for name, tls_cipher, ssl_cipher, issue in testList :
            offer = False
            if self._result.getResult('offer_ssl2') and ssl_cipher != None :
                # Test SSL2
                if self.testSSL2(ssl_cipher) :
                    offer = True
                    if issue :
                        for cipherHex in splitCipherHexStringSSL2(ssl_cipher) :
                            self._result.addVulnerabilityToCipher(cipherHex, 'SSLv2.0', '<b style="color:red;">%s</b>' % name)

            for version in getSupportedTLSVersion(self._result) :
                if self.testTLS(tls_cipher, version) :
                    offer = True
                    if issue :
                        for cipherHex in splitCipherHexStringTLS(tls_cipher) :
                            self._result.addVulnerabilityToCipher(cipherHex, versionIntToString(version), '<b style="color:red;">%s</b>' % name)
            self._result.addResult('cipher_'+name, offer)
            if offer and issue :
                self._result.addVulnerability('cipher_'+name)
                