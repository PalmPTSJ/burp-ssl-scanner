from test_details import *

class Result :
    
    def __init__(self):
        self._resultDict = {}
        self.vulnerabilityList = []
        pass

    def addVulnerability(self, severity, name) :
        # print 
        print "VULNERABILITY FOUND: [%s] %s" % (severity, name)
        self.vulnerabilityList.append("[%s] %s" % (severity, name))
        # Add to Burp issue
        pass

    def printResult(self, field) :
        try:
            return "%s: %s" % (POSSIBLE_TESTS[field], POSSIBLE_RESULTS[field][self.getResult(field)])
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


