from util import tryHandshake, getHighestTLSVersion, addNecessaryExtensionToHello
from TLS_protocol import ClientHello

class CrimeTest :
    def __init__(self, result, host, port) :
        self._result = result
        self._host = host
        self._port = port
    
    def start(self) :
        version = getHighestTLSVersion(self._result)
        if version == -1 :
            print("[CRIME] No valid TLS version found")
            self._result.addResult('crime_tls', False)
        else :
            print("Testing CRIME (TLS) with TLS version ",version)

            hello = ClientHello()
            hello.compression = '01' # DEFLATE ONLY
            hello.version = version
            hellohex = hello.createAsHex()

            self._result.addResult('crime_tls',tryHandshake(self._host, self._port, addNecessaryExtensionToHello(hellohex, self._host)) >= 0 )
            if self._result.getResult('crime_tls') :
                self._result.addVulnerability('CRITICAL', 'Vulnerable to CRIME (TLS)')