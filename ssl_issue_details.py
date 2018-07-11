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
