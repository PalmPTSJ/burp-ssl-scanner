from test_details import *
from ssl_issue_details import SSLIssue
from java.lang import Runnable
from javax.swing import SwingUtilities
class Result :
    
    def __init__(self, url, callbacks, helpers):
        self._resultDict = {}
        self.url = url
        self.callbacks = callbacks
        self.helpers = helpers

    def addVulnerability(self, issueKey) :
        # print 
        print "VULNERABILITY FOUND: [%s]" % (issueKey)
        # Add to Burp issue
        issue = SSLIssue(issueKey, self.url, self.helpers)
        SwingUtilities.invokeLater(
                ScannerRunnable(self.callbacks.addScanIssue, (issue, ))
        )

    def printResult(self, field) :
        try:
            return "%s: %s" % (POSSIBLE_TESTS[field]['name'], POSSIBLE_TESTS[field]['result'][self.getResult(field)])
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


class ScannerRunnable(Runnable):
    def __init__(self, func, args):
        self.func = func
        self.args = args

    def run(self):
        self.func(*self.args)