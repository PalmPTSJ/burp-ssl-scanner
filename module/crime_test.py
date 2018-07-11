from util import getHighestTLSVersion, addNecessaryExtensionToHelloObject, getServerHelloObject
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
            print("[CRIME] Testing CRIME (TLS) with TLS version ",version)

            hello = ClientHello()
            hello.compression = '0100' # DEFLATE & null
            hello.version = version
            hello = addNecessaryExtensionToHelloObject(hello, self._host)
            hellohex = hello.createAsHex()

            serverHello = getServerHelloObject(self._host, self._port, hellohex)

            self._result.addResult('crime_tls', serverHello.compressionMethod == '01' )
            if self._result.getResult('crime_tls') :
                self._result.addVulnerability('crime_tls')