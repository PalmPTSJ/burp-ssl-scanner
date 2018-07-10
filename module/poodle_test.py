from util import tryHandshake, addNecessaryExtensionToHello

cbc_hello = '16030000f1010000ed030054511e7adeadbeef3133070000000000cfbd3904cc160a8503909f770433d4de0000c6c014c00ac022c021c020009100390038003700360088008700860085c019003a0089c00fc0050035c03600840095008dc013c009c01fc01ec01d0033003200310030009a0099009800970045004400430042c0180034009b0046c00ec004002fc03500900096004100070094008c00210025c012c008c01cc01bc01a001600130010000dc017001bc00dc003000a0093008b001f0023c034008f006300150012000f000c001a00620009001e00220014001100190008000600270026002a0029000b000e00ff0100'
class PoodleTest :
    def __init__(self, result, host, port) :
        self._result = result
        self._host = host
        self._port = port
    
    def start(self) :
        self._result.addResult('poodle_ssl3', self._result.getResult('offer_ssl3') and tryHandshake(self._host, self._port, addNecessaryExtensionToHello(cbc_hello, self._host)) != -1)
        if self._result.getResult('poodle_ssl3') :
            if not self._result.getResult('fallback_support') :
                self._result.addVulnerability('CRITICAL', 'Vulnerable to POODLE SSLv3 and FALLBACK_SCSV not supported')
            else :
                if all([not self._result.getResult(protocol) for protocol in ["offer_tls10","offer_tls11","offer_tls12"]]) :
                    self._result.addVulnerability('CRITICAL', 'Vulnerable to POODLE SSLv3 and SSLv3 is the highest SSL version')
                else :
                    self._result.addVulnerability('LOW', 'Vulnerable to POODLE SSLv3 but mitigated by FALLBACK_SCSV')
