class Result :
    
    def __init__(self):
        self._resultDict = {}
        pass

    def addVulnerability(self, severity, name) :
        # print 
        print "VULNERABILITY FOUND: [%s] %s" % (severity, name)
        # Add to Burp issue
        pass

    def printResult(self, fields) :
        for field in fields :
            print "%s %s" % (field, self._resultDict[field])

    def addResult(self, field, val) :
        print "%s %s" % (field, val)
        self._resultDict[field] = val

    def requireResult(self, fields) :
        for field in fields :
            if field not in self._resultDict :
                return False
        return True

    def getResult(self, field) :
        return self._resultDict[field]


