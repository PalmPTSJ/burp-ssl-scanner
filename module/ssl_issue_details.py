from burp import IScanIssue
from test_details import *
from result import *

class SSLIssue(IScanIssue):
    def __init__(self, issueInternalType, url):
        self.issueInternalType = issueInternalType
        self.url = url
    
    def getUrl(self):
        return self.url

    def getIssueInternalType(self):
        return self.issueInternalType

    def getIssueName(self):
        return True

    def getIssueType(self):
        return True

    def getSeverity(self):
        return "Low"
        
    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Something"

    def getRemediationBackground(self):
        return "Something"

    def getIssueDetail(self):
        return "Something special"
    
    def getRemediationDetail(self):
        return "Something special"

    def getHttpService(self):
        return None
