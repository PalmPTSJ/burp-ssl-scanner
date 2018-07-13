from test_details import *
from ssl_issue_details import SSLIssue
from java.lang import Runnable
from javax.swing import SwingUtilities
class Result :
    
    def __init__(self, url, callbacks, helpers, addToSitemap):
        self._resultDict = {}
        self.url = url
        self.callbacks = callbacks
        self.helpers = helpers
        self.addToSitemap = addToSitemap
        self.issueList = []

    def addVulnerability(self, issueKey, additionalInfo = None) :
        print "VULNERABILITY FOUND: [%s] - %s" % (issueKey, additionalInfo)

        # Add issue to summary list
        issue = SSLIssue(issueKey, self.url, self.helpers)
        self.issueList.append('<li>[%s] %s</li>' % (issue.getSeverity(), issue.getIssueName().replace('[SSL Scanner] ','')))

        # Add to Burp issue
        if self.addToSitemap  :
            scanIssues = self.callbacks.getScanIssues(self.url.getProtocol()+"://"+self.url.getHost())
            # Check if the issue already exists
            for oldIssue in scanIssues :
                try :
                    if oldIssue.getIssueName() == issue.getIssueName() :
                        # exists
                        break
                except BaseException as e :
                    pass
            else :
                # Not exists, add new issue
                SwingUtilities.invokeLater(
                        ScannerRunnable(self.callbacks.addScanIssue, (issue, ))
                )

    def printAllIssue(self) :
        return  '<ul>' + ''.join(self.issueList) + '</ul>'

    def printResult(self, field) :
        try:
            return "<b>%s</b>: %s" % (POSSIBLE_TESTS[field]['name'], POSSIBLE_TESTS[field]['result'][self.getResult(field)])
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