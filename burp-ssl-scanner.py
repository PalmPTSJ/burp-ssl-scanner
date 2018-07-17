try:
    from burp import IBurpExtender
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import ITab
    from burp import IMessageEditor
    from burp import IContextMenuFactory
    from burp import IContextMenuInvocation
    from burp import IHttpRequestResponse
    from java.io import PrintWriter, File, FileWriter
    from java.lang import Runnable
    from javax.swing import (JTable, JScrollPane, JSplitPane, JButton, JPanel,
                             JTextField, JLabel, SwingConstants, JDialog, Box,
                             JCheckBox, JMenuItem, SwingUtilities, JOptionPane,
                             BoxLayout, JPopupMenu, JFileChooser, JTextPane)

    from javax.swing.border import EmptyBorder
    from javax.swing.table import AbstractTableModel
    from java.awt import (GridLayout, BorderLayout, FlowLayout, Dimension, Point)
    from java.net import URL, MalformedURLException
    from java.util import ArrayList

    from threading import Thread, Event

    import sys
    import os
    import socket

    import time

    import json

    from module import *

except ImportError as e:
    print e
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

VERSION = '0.1'


class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        print "Loading..."

        self._callbacks = callbacks
        self._callbacks.setExtensionName('Burp SSL Scanner')
        # self._callbacks.registerScannerCheck(self)
        # self._callbacks.registerExtensionStateListener(self)
        self._helpers = callbacks.getHelpers()

        # initialize the main scanning event and thread
        self.scanningEvent = Event()
        self.scannerThread = None
        self.targetURL = None

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setBorder(EmptyBorder(20, 20, 20, 20))
        
        # sub split pane (top)
        self._topPanel = JPanel(BorderLayout(10, 10))
        self._topPanel.setBorder(EmptyBorder(0, 0, 10, 0))

        # Setup Panel :    [Target: ] [______________________] [START BUTTON]
        self.setupPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))

        self.setupPanel.add(
            JLabel("Target:", SwingConstants.LEFT), BorderLayout.LINE_START)

        self.hostField = JTextField('', 50)
        self.setupPanel.add(self.hostField)

        self.toggleButton = JButton(
            'Start scanning', actionPerformed=self.startScan)
        self.setupPanel.add(self.toggleButton)

        if 'Professional' in callbacks.getBurpVersion()[0] :
            self.addToSitemapCheckbox = JCheckBox('Add to sitemap', True)
        else :
            self.addToSitemapCheckbox = JCheckBox('Add to sitemap (requires Professional version)', False)
            self.addToSitemapCheckbox.setEnabled(False)
        self.setupPanel.add(self.addToSitemapCheckbox)

        self._topPanel.add(self.setupPanel, BorderLayout.PAGE_START)
        
        # Status bar
        self.scanStatusPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))

        self.scanStatusPanel.add(JLabel("Status: ", SwingConstants.LEFT))

        self.scanStatusLabel = JLabel("Ready to scan", SwingConstants.LEFT)
        self.scanStatusPanel.add(self.scanStatusLabel)

        self._topPanel.add(self.scanStatusPanel, BorderLayout.LINE_START)

        self._splitpane.setTopComponent(self._topPanel)

        # bottom panel 
        self._bottomPanel = JPanel(BorderLayout(10, 10))
        self._bottomPanel.setBorder(EmptyBorder(10, 0, 0, 0))

        self.initialText = ('<h1 style="color: red;">Burp SSL Scanner<br />'
                            'Please note that TLS1.3 is still not supported by this extension.</h1>')
        self.currentText = self.initialText

        self.textPane = JTextPane()
        self.textScrollPane = JScrollPane(self.textPane)
        self.textPane.setContentType("text/html")
        self.textPane.setText(self.currentText)
        self.textPane.setEditable(False)

        self._bottomPanel.add(self.textScrollPane, BorderLayout.CENTER)

        self.savePanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.saveButton = JButton('Save to file', actionPerformed=self.saveToFile)
        self.saveButton.setEnabled(False)
        self.savePanel.add(self.saveButton)

        self.clearScannedHostButton = JButton('Clear scanned host', actionPerformed=self.clearScannedHost)
        self.savePanel.add(self.clearScannedHostButton)
        self.savePanel.add(JLabel("Clear hosts that were scanned by active scan to enable rescanning", SwingConstants.LEFT))

        self._bottomPanel.add(self.savePanel, BorderLayout.PAGE_END)

        self._splitpane.setBottomComponent(self._bottomPanel)

        callbacks.customizeUiComponent(self._splitpane)

        callbacks.addSuiteTab(self)
        
        print "SSL Scanner tab loaded"


        self.scannerMenu = ScannerMenu(self)
        callbacks.registerContextMenuFactory(self.scannerMenu)
        print "SSL Scanner custom menu loaded"


        self.scannerCheck = ScannerCheck(self)
        callbacks.registerScannerCheck(self.scannerCheck)
        print "SSL Scanner check registered"

        projectConfig = json.loads(self._callbacks.saveConfigAsJson())
        scanAccuracy = projectConfig['scanner']['active_scanning_optimization']['scan_accuracy']
        scanSpeed = projectConfig['scanner']['active_scanning_optimization']['scan_speed']

        print(scanAccuracy, scanSpeed)

        self.scannedHost = []

        print 'SSL Scanner loaded'
        
    def startScan(self, ev) :

        host = self.hostField.text
        self.scanningEvent.set()
        if(len(host) == 0):
            return
        if host.find("://") == -1:
            host = "https://" + host 
        try:
            self.targetURL = URL(host)
            if(self.targetURL.getPort() == -1):
                self.targetURL = URL("https", self.targetURL.getHost(), 443, "/")
            self.hostField.setEnabled(False)
            self.toggleButton.setEnabled(False)
            self.saveButton.setEnabled(False)
            self.addToSitemapCheckbox.setEnabled(False)
            self.currentText = self.initialText
            self.textPane.setText(self.currentText)
            self.updateText("<h2>Scanning %s:%d</h2>" % (self.targetURL.getHost(), self.targetURL.getPort()))
            print("Scanning %s:%d" % (self.targetURL.getHost(), self.targetURL.getPort()))
            self.scannerThread = Thread(target=self.scan, args=(self.targetURL, ))
            self.scannerThread.start()
        except BaseException as e:
            self.saveButton.setEnabled(False)
            print(e)
            return

    def scan(self, url, usingBurpScanner=False):

        def setScanStatusLabel(text) :
            if not usingBurpScanner :
                SwingUtilities.invokeLater(
                    ScannerRunnable(self.scanStatusLabel.setText, 
                                    (text,)))
                                
        def updateResultText(text) :
            if not usingBurpScanner :
                SwingUtilities.invokeLater(
                    ScannerRunnable(self.updateText, (text, )))

        if usingBurpScanner :
            res = result.Result(url, self._callbacks, self._helpers, False)
        else :
            res = result.Result(url, self._callbacks, self._helpers, self.addToSitemapCheckbox.isSelected())

        host, port = url.getHost(), url.getPort()

        ### Get project configuration
        projectConfig = json.loads(self._callbacks.saveConfigAsJson())
        # scanAccuracy: minimise_false_negatives, normal, minimise_false_positives
        scanAccuracy = projectConfig['scanner']['active_scanning_optimization']['scan_accuracy']
        # scanSpeed: fast, normal, thorough
        scanSpeed = projectConfig['scanner']['active_scanning_optimization']['scan_speed']

        updateResultText('<h2>Scanning speed: %s</h2> %s' % (scanSpeed, test_details.SCANNING_SPEED_INFO[scanSpeed]))
        updateResultText('<h2>Scanning accuracy: %s</h2> %s' % (scanAccuracy, test_details.SCANNING_ACCURACY_INFO[scanAccuracy]))

        try :
            setScanStatusLabel("Checking for supported SSL/TLS versions")
            con = connection_test.ConnectionTest(res, host, port, scanSpeed, scanAccuracy)
            con.start()
            conResultText = '<hr /><br /><h3>' + res.printResult('connectable') + '</h3>' + \
                '<ul><li>' + res.printResult('offer_ssl2') + '</li>' + \
                '<li>' + res.printResult('offer_ssl3') + '</li>' + \
                '<li>' + res.printResult('offer_tls10') + '</li>' + \
                '<li>' + res.printResult('offer_tls11') + '</li>' + \
                '<li>' + res.printResult('offer_tls12') + '</li></ul>'
            updateResultText(conResultText)

            
            if not res.getResult('connectable') :
                updateResultText("<h2>Scan terminated (Connection failed)</h2>")
                raise BaseException('Connection failed')

            setScanStatusLabel("Checking for supported cipher suites (This can take a long time)")
            supportedCipher = supportedCipher_test.SupportedCipherTest(res, host, port, scanSpeed, scanAccuracy)
            supportedCipher.start()

            
            setScanStatusLabel("Checking for Cipherlist")
            cipher = cipher_test.CipherTest(res, host, port, scanSpeed, scanAccuracy)
            cipher.start()
            cipherResultText = '<h3>Available ciphers:</h3>' + \
                '<ul><li>' + res.printResult('cipher_NULL') + '</li>' + \
                '<li>' + res.printResult('cipher_ANON') + '</li>' + \
                '<li>' + res.printResult('cipher_EXP') + '</li>' + \
                '<li>' + res.printResult('cipher_LOW') + '</li>' + \
                '<li>' + res.printResult('cipher_WEAK') + '</li>' + \
                '<li>' + res.printResult('cipher_3DES') + '</li>' + \
                '<li>' + res.printResult('cipher_HIGH') + '</li>' + \
                '<li>' + res.printResult('cipher_STRONG') + '</li></ul>' 
            updateResultText(cipherResultText)
            

            setScanStatusLabel("Checking for Heartbleed")
            heartbleed = heartbleed_test.HeartbleedTest(res, host, port, scanSpeed, scanAccuracy)
            heartbleed.start()
            heartbleedResultText = res.printResult('heartbleed')
            updateResultText(heartbleedResultText)
            

            setScanStatusLabel("Checking for CCS Injection")
            ccs = ccs_test.CCSTest(res, host, port, scanSpeed, scanAccuracy)
            ccs.start()
            ccsResultText = res.printResult('ccs_injection')
            updateResultText(ccsResultText)

            
            setScanStatusLabel("Checking for TLS_FALLBACK_SCSV")
            fallback = fallback_test.FallbackTest(res, host, port, scanSpeed, scanAccuracy)
            fallback.start()
            fallbackResultText = res.printResult('fallback_support')
            updateResultText(fallbackResultText)


            setScanStatusLabel("Checking for POODLE (SSLv3)")
            poodle = poodle_test.PoodleTest(res, host, port, scanSpeed, scanAccuracy)
            poodle.start()
            poodleResultText = res.printResult('poodle_ssl3')
            updateResultText(poodleResultText)
            

            setScanStatusLabel("Checking for SWEET32")
            sweet32 = sweet32_test.Sweet32Test(res, host, port, scanSpeed, scanAccuracy)
            sweet32.start()
            sweet32ResultText = res.printResult('sweet32')
            updateResultText(sweet32ResultText)
            

            setScanStatusLabel("Checking for DROWN")
            drown = drown_test.DrownTest(res, host, port, scanSpeed, scanAccuracy)
            drown.start()
            drownResultText = res.printResult('drown')
            updateResultText(drownResultText)
            

            setScanStatusLabel("Checking for FREAK")
            freak = freak_test.FreakTest(res, host, port, scanSpeed, scanAccuracy)
            freak.start()
            freakResultText = res.printResult('freak')
            updateResultText(freakResultText)
            

            setScanStatusLabel("Checking for LUCKY13")
            lucky13 = lucky13_test.Lucky13Test(res, host, port, scanSpeed, scanAccuracy)
            lucky13.start()
            lucky13ResultText = res.printResult('lucky13')
            updateResultText(lucky13ResultText)
            

            setScanStatusLabel("Checking for CRIME")
            crime = crime_test.CrimeTest(res, host, port, scanSpeed, scanAccuracy)
            crime.start()
            crimeResultText = res.printResult('crime_tls')
            updateResultText(crimeResultText)
            

            setScanStatusLabel("Checking for BREACH")
            breach = breach_test.BreachTest(res, host, port, scanSpeed, scanAccuracy)
            breach.start(self._callbacks, self._helpers)
            breachResultText = res.printResult('breach')
            updateResultText(breachResultText)


            setScanStatusLabel("Checking for BEAST")
            beast = beast_test.BeastTest(res, host, port, scanSpeed, scanAccuracy)
            beast.start()
            beastResultText = res.printResult('beast')
            updateResultText(beastResultText)


            setScanStatusLabel("Checking for LOGJAM")
            logjam = logjam_test.LogjamTest(res, host, port, scanSpeed, scanAccuracy)
            logjam.start()
            logjamResultText = res.printResult('logjam_export') + '<br />' + res.printResult('logjam_common') 
            updateResultText(logjamResultText)
            

            updateResultText('<h2>Finished scanning</h2><br /><hr /><br /><h2>Summary</h2>')

            updateResultText('<h2>Supported ciphers (by Protocol)</h2>')
            updateResultText(res.printCipherList())
            updateResultText('<h2>Supported ciphers (by Vulnerability)</h2>')
            updateResultText(res.printCipherListByVulns())

            updateResultText('<h2>Issues found</h2>')
            updateResultText(res.printAllIssue())

        except BaseException as e :
            print(e)
            setScanStatusLabel("An error occurred. Please refer to the output/errors tab for more information.")
            time.sleep(2)

        if usingBurpScanner :
            return res.getAllIssue()
        else :
            self.scanningEvent.clear()
            SwingUtilities.invokeLater(
                    ScannerRunnable(self.toggleButton.setEnabled, (True, ))
            )
            SwingUtilities.invokeLater(
                    ScannerRunnable(self.hostField.setEnabled, (True, ))
            )
            SwingUtilities.invokeLater(
                    ScannerRunnable(self.saveButton.setEnabled, (True, ))
            )
            if 'Professional' in self._callbacks.getBurpVersion()[0] :
                SwingUtilities.invokeLater(
                    ScannerRunnable(self.addToSitemapCheckbox.setEnabled, (True, ))
                )
            setScanStatusLabel("Ready to scan")
        print("Finished scanning")

    def updateText(self, stringToAppend):
        self.currentText += ('<br />' + stringToAppend)
        self.textPane.setText(self.currentText)

    def saveToFile(self, event):
        fileChooser = JFileChooser()
        if not (self.targetURL is None):
            fileChooser.setSelectedFile(File("Burp_SSL_Scanner_Result_%s.html" \
                % (self.targetURL.getHost())))
        else:
            fileChooser.setSelectedFile(File("Burp_SSL_Scanner_Result.html"))
        if (fileChooser.showSaveDialog(self.getUiComponent()) == JFileChooser.APPROVE_OPTION):
            fw = FileWriter(fileChooser.getSelectedFile())
            fw.write(self.textPane.getText())
            fw.flush()
            fw.close()
            print "Saved results to disk"

    def clearScannedHost(self, event) :
        self.scannedHost = []

    def addHostToScannedList(self, host, port) :
        self.scannedHost.append([host, port])

    def getTabCaption(self):
        return "SSL Scanner"

    def getUiComponent(self):
        return self._splitpane
    
class ScannerMenu(IContextMenuFactory):
    def __init__(self, scannerInstance):
        self.scannerInstance = scannerInstance

    def createMenuItems(self, contextMenuInvocation):
        self.contextMenuInvocation = contextMenuInvocation
        sendToSSLScanner = JMenuItem(
            "Send URL to SSL Scanner", actionPerformed=self.getSentUrl)
        menuItems = ArrayList()
        menuItems.add(sendToSSLScanner)
        return menuItems

    def getSentUrl(self, event):
        for selectedMessage in self.contextMenuInvocation.getSelectedMessages():
            if (selectedMessage.getHttpService() != None):
                try:
                    url = self.scannerInstance._helpers.analyzeRequest(
                        selectedMessage.getHttpService(),
                        selectedMessage.getRequest()).getUrl()
                    print "URL: " + url.toString()
                    self.scannerInstance.hostField.setText(url.toString())
                except:
                    self.scannerInstance._callbacks.issueAlert(
                        "Cannot get URL from the currently selected message " +
                        str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1]))
            else:
                self.scannerInstance._callbacks.issueAlert(
                    "The selected request is null.")


class ScannerCheck(IScannerCheck) :
    def __init__(self, scannerInstance) :
        self.scannerInstance = scannerInstance

    def doActiveScan(self, baseReqRes, insPoint) :
        # Get URL from request and check if the host has already been scanned by our tool
        httpService = baseReqRes.getHttpService()
        host, port, protocol = httpService.getHost(), httpService.getPort(), httpService.getProtocol()

        print "[SSL Scanner] Do active scan: ",host,port,protocol
        # Check if already scanned
        for scannedHost, scannedPort in self.scannerInstance.scannedHost :
            if scannedHost == host and scannedPort == port :
                print "[SSL Scanner] The host has already been scanned, aborting"
                self.scannerInstance._callbacks.issueAlert("The host %s:%d has already been scanned (Use [Clear scanned host] button to enable rescanning)" % (host, port))
                break
        else :
            self.scannerInstance.addHostToScannedList(host, port)
            self.scannerInstance._callbacks.issueAlert("Scanning %s:%d" % (host, port))
            issues = self.scannerInstance.scan(URL(protocol, host, port, "/"), True)
            self.scannerInstance._callbacks.issueAlert("Scan finished for %s:%d" % (host, port))

            return issues
        return None
    
    def doPassiveScan(self, baseReqRes) :
        print "[SSL Scanner] Do passive scan"
        return None

    def consolidateDuplicateIssues(self, old, new) :
        if old.getIssueName() == new.getIssueName() :
            return 1 # Use only new issue
        return 0 # Use both issue


class ScannerRunnable(Runnable):
    def __init__(self, func, args):
        self.func = func
        self.args = args

    def run(self):
        self.func(*self.args)

