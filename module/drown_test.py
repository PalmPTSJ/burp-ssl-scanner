
from util import *
import connection_test

class DrownTest(Test) :
    def start(self) :
        # Connect using SSLv2
        if self._result.getResult('offer_ssl2') :
            try :
                data = sendData(self._host, self._port, connection_test.sslv2_hello.decode('hex'))
                #print("DATA",data)
                # Byte 10-11 = Cipher suite length
                cipherLength = ord(data[9])*256 + ord(data[10])
                if cipherLength > 0:
                    print("Found %d ciphers" % (cipherLength // 3))
                    self._result.addResult('drown', True)
                else :
                    print("Offer SSLv2 but no ciphersuite found")
                    self._result.addResult('drown', False)
            except BaseException as e :
                print("Error while parsing SSLv2",e)
                self._result.addResult('drown', False)
        else :
            self._result.addResult('drown', False)

        if self._result.getResult('drown') :
            self._result.addVulnerability('drown')