from test_details import *
from util import *
from ssl_issue_details import SSLIssue
from java.lang import Runnable
from javax.swing import SwingUtilities
class Result :
    
    def __init__(self, url, callbacks, helpers, addToSitemap):
        self._resultDict = {}
        self._resultDict['ciphers_by_vulns'] = {}
        self.url = url
        self.callbacks = callbacks
        self.helpers = helpers
        self.addToSitemap = addToSitemap
        self.issueList = [] # Issue list

    def addVulnerability(self, issueKey, additionalInfo = None) :
        print "TEST FOUND: [%s] - %s" % (issueKey, additionalInfo)

        # Add issue to summary list
        issue = SSLIssue(issueKey, self.url, self.helpers)
        if not (additionalInfo is None):
            issue.setIssueDetail(additionalInfo)

        self.issueList.append(issue)

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

    def getAllIssue(self) :
        return self.issueList

    def printAllIssue(self) :
        return  '<ul>' + ''.join(['<li>[%s] %s</li>' % (issue.getSeverity(), issue.getIssueName().replace('[SSL Scanner] ','')) for issue in self.getAllIssue()]) + '</ul>'

    def printResult(self, field) :
        try:
            return "<b>%s</b>: %s" % (POSSIBLE_TESTS[field]['name'], POSSIBLE_TESTS[field]['result'][self.getResult(field)])
        except KeyError:
            return "Test does not exist"
    
    def addVulnerabilityToCipher(self, cipherHex, versionString, vuln) :
        cipherList = self.getResult('supported_ciphers')[versionString]
        #print("Adding",cipherHex,versionString,vuln)
        for cipher in cipherList :
            if cipher['byte'] == cipherHex :
                cipher['vulnerabilities'].append(vuln)
                if not (vuln in self._resultDict['ciphers_by_vulns']):
                    self._resultDict['ciphers_by_vulns'][vuln] = []
                self._resultDict['ciphers_by_vulns'][vuln].append(cipher['name'] + (" (%s)" % versionString))
                break

    def printCipherList(self) :
        try:
            resultList = ""
            for protocol in ['SSLv2.0', 'SSLv3.0', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2']:  
                if protocol not in self.getResult('supported_ciphers') :
                    continue  

                if(len(self.getResult('supported_ciphers')[protocol]) > 0):
                    resultList += "<b>" + protocol + "</b><br /><ul>"
                    for cipher in self.getResult('supported_ciphers')[protocol] :
                        if len(cipher['vulnerabilities']) == 0 :
                            resultList += "<li>%s</li>"  % cipher['name']
                        else :
                            resultList += "<li>%s: %s</li>"  % (cipher['name'], ' '.join(cipher['vulnerabilities']))
                    resultList += "</ul>"
            #print(resultList)
            # check if we are printing the full list for the summary
            self.addVulnerability('supported_ciphers', resultList) # Add information to sitemap
            return resultList
        except:
            return ("The cipher list has not been generated yet.<br />"
                    "An error might have occurred during the cipher enumeration stage.")

    def printCipherListByVulns(self):
        try:
            resultList = ""
            for vuln in self._resultDict['ciphers_by_vulns']:
                resultList += "<b>" + vuln + "</b><br /><ul>"
                for cipher in sorted(self._resultDict['ciphers_by_vulns'][vuln]):
                    resultList += "<li>%s</li>" % cipher
                resultList += "</ul>"
            return resultList
        except BaseException as e:
            print e
            return ("The cipher list has not been generated yet.<br />"
                    "An error might have occurred during the cipher enumeration stage.")

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