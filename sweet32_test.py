
from util import tryHandshake, getHighestTLSVersion, modifyHelloVersion

sweet32_hello = '16030100D4010000D0030354511E7ADEADBEEF3133070000000000CFBD3904CC160A8503909F770433D4DE00002EC012C008C01CC01BC01A001600130010000DC017001BC00DC003000A0093008B001F0023C034008FFEFFFFE000FF010000790023000033740000000D0020001E060106020603050105020503040104020403030103020303020102020203000A003E003C000E000D0019001C001E000B000C001B00180009000A001A00160017001D000800060007001400150004000500120013000100020003000F00100011000B00020100000F000101'
class Sweet32Test :
    def __init__(self, result, host, port) :
        self._result = result
        self._host = host
        self._port = port
    
    def start(self) :
        version = getHighestTLSVersion(self._result)
        if version == -1 :
            print("[SWEET32] No valid TLS version found")
            self._result.addResult('sweet32', False)
            return
        print("Testing SWEET32 with TLS version ",version)
        self._result.addResult('sweet32',tryHandshake(self._host, self._port, modifyHelloVersion(sweet32_hello,version)) != -1)
        if self._result.getResult('sweet32') :
            self._result.addVulnerability('LOW', 'Vulnerable to SWEET32')