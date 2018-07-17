from util import *

cipherHexFull = 'c014c00ac022c021c020009100390038003700360088008700860085c019003a0089c00fc0050035c03600840095008dc013c009c01fc01ec01d0033003200310030009a0099009800970045004400430042c0180034009b0046c00ec004002fc03500900096004100070094008c00210025c012c008c01cc01bc01a001600130010000dc017001bc00dc003000a0093008b001f0023c034008f006300150012000f000c001a00620009001e00220014001100190008000600270026002a0029000b000e'

cbc_hello = '16030000f1010000ed030054511e7adeadbeef3133070000000000cfbd3904cc160a8503909f770433d4de0000c6c014c00ac022c021c020009100390038003700360088008700860085c019003a0089c00fc0050035c03600840095008dc013c009c01fc01ec01d0033003200310030009a0099009800970045004400430042c0180034009b0046c00ec004002fc03500900096004100070094008c00210025c012c008c01cc01bc01a001600130010000dc017001bc00dc003000a0093008b001f0023c034008f006300150012000f000c001a00620009001e00220014001100190008000600270026002a0029000b000e00ff0100'
class PoodleTest(Test) :
    def start(self) :
        self._result.addResult('poodle_ssl3', self._result.getResult('offer_ssl3') and tryHandshake(self._host, self._port, addNecessaryExtensionToHello(cbc_hello, self._host)) != -1)
        if self._result.getResult('poodle_ssl3') :
            if not self._result.getResult('fallback_support') :
                print("[POODLE] Vulnerable to POODLE without TLS_FALLBACK_SCSV support")
                self._result.addVulnerability('poodle_ssl3')
            else :
                if all([not self._result.getResult(protocol) for protocol in ["offer_tls10","offer_tls11","offer_tls12"]]) :
                    print("[POODLE] Vulnerable to POODLE and SSLv3 is the highest version supported")
                    self._result.addVulnerability('poodle_ssl3')
                else :
                    print("[POODLE] Vulnerable to POODLE but mitigated by TLS_FALLBACK_SCSV")
                    self._result.addVulnerability('poodle_ssl3')

            for cipherHex in splitCipherHexStringTLS(cipherHexFull) :
                self._result.addVulnerabilityToCipher(cipherHex, 'SSLv3.0', '<b style="color:red;">POODLE</b>')
