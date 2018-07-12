from burp import IScanIssue
from burp import IHttpService
from test_details import *
from result import *

class SSLIssue(IScanIssue):
    def __init__(self, issueKey, url, helpers):
        self.issueKey = issueKey
        self._url = url
        self.helpers = helpers
    
    def getUrl(self):
        return self._url

    def getIssueInternalType(self):
        return POSSIBLE_TESTS[self.issueKey]['internalType']

    def getIssueName(self):
        return "[SSL Scanner] "+POSSIBLE_TESTS[self.issueKey]['name']

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
        self._issueDetail = issueDetail

    def getIssueDetail(self):
        try:
            return self._issueDetail
        except AttributeError:
            return None

    def setRemediationDetail(self, remediationDetail):
        self._remediationDetail = remediationDetail

    def getRemediationDetail(self):
        try:
            return self._remediationDetail
        except AttributeError:
            return None

    def getHttpMessages(self) :
        return []

    def getHttpService(self):
        return self.helpers.buildHttpService(self._url.getHost(), self._url.getPort(), self._url.getProtocol())
