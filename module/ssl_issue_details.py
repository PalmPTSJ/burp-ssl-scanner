from burp import IScanIssue
from burp import IHttpService
from test_details import *
from result import *

class SSLIssue(IScanIssue):
    def __init__(self, issueKey, url, helpers):
        self.issueKey = issueKey
        self.url = url
        self.helpers = helpers
    
    def getUrl(self):
        return self.url

    def getIssueInternalType(self):
        return POSSIBLE_TESTS[self.issueKey]['internalType']

    def getIssueName(self):
        return POSSIBLE_TESTS[self.issueKey]['name']

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return POSSIBLE_TESTS[self.issueKey]['severity']
        
    def getConfidence(self):
        return POSSIBLE_TESTS[self.issueKey]['confidence']

    def getIssueBackground(self):
        return POSSIBLE_TESTS[self.issueKey]['issueBackground']

    def getRemediationBackground(self):
        return POSSIBLE_TESTS[self.issueKey]['remediationBackground']

    def setIssueDetail(self, issueDetail):
        self.issueDetail = issueDetail

    def getIssueDetail(self):
        try:
            return self.issueDetail
        except AttributeError:
            return None

    def setRemediationDetail(self, remediationDetail):
        self.remediationDetail = remediationDetail

    def getRemediationDetail(self):
        try:
            return self.remediationDetail
        except AttributeError:
            return None

    def getHttpService(self):
        return self.helpers.buildHttpService(self.url.getHost(), self.url.getPort(), self.url.getProtocol())
