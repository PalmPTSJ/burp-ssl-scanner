POSSIBLE_TESTS = {
    'connectable': 'SSL/TLS Connection Test',
    'offer_ssl2': 'Offer SSLv2',
    'offer_ssl3': 'Offer SSLv3',
    'offer_tls10': 'Offer TLS1.0',
    'offer_tls11': 'Offer TLS1.1',
    'offer_tls12': 'Offer TLS1.2',
    'heartbleed': 'Heartbleed',
    'ccs_injection': 'CCS Injection',
    'fallback_support': 'TLS_FALLBACK_SCSV Support',
    'poodle_ssl3': 'POODLE (SSLv3)',
    'sweet32': 'SWEET32',
    'drown': 'DROWN',
    'freak': 'FREAK',
    'lucky13' : 'LUCKY13',
    'crime_tls' : 'CRIME (TLS)',
    'breach' : 'BREACH',
    'cipher_NULL' : 'NULL Cipher',
    'cipher_ANON' : 'ANON Cipher',
    'cipher_EXP' : 'EXP Cipher',
    'cipher_LOW' : 'LOW Cipher',
    'cipher_WEAK' : 'WEAK Cipher',
    'cipher_3DES' : '3DES Cipher',
    'cipher_HIGH' : 'HIGH Cipher',
    'cipher_STRONG' : 'STRONG Cipher'
}
class Result :
    
    def __init__(self):
        self._resultDict = {}
        pass

    def addVulnerability(self, severity, name) :
        # print 
        print "VULNERABILITY FOUND: [%s] %s" % (severity, name)
        # Add to Burp issue
        pass

    def printResult(self, field) :
        try:
            return "%s %s" % (POSSIBLE_TESTS[field], self.getResult(field))
        except KeyError:
            return "Test does not exist"

    def addResult(self, field, val) :
        print "%s %s" % (field, val)
        self._resultDict[field] = val

    def requireResult(self, fields) :
        for field in fields :
            if field not in self._resultDict :
                return False
        return True

    def getResult(self, field) :
        try: 
            return self._resultDict[field]
        except KeyError:
            return False


