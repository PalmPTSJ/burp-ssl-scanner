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
                             BoxLayout, JPopupMenu, JFileChooser)

    from javax.swing.border import EmptyBorder
    from javax.swing.table import AbstractTableModel
    from java.awt import (GridLayout, BorderLayout, FlowLayout, Dimension, Point)
    from java.net import URL
    from java.util import ArrayList

    from threading import Thread, Event

    import sys
    import os
    import socket
    from java.lang import System

    import re
    import hashlib

    import ssl
    import time

    import result
    import connection_test
    import heartbleed_test
    import ccs_test
    import fallback_test
    import poodle_test
    import sweet32_test
    import drown_test
    import freak_test
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

        self.textEditorInstance = callbacks.createTextEditor()
        self.textEditorInstance.setEditable(False)
        initialText = 'Press "Start scanning" to get started.'
        self.textEditorInstance.setText(self._helpers.stringToBytes(initialText))
        self._bottomPanel.add(self.textEditorInstance.getComponent(), BorderLayout.CENTER)

        self.savePanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.savePanel.add(JButton('Save to file', actionPerformed=self.saveToFile))
        self._bottomPanel.add(self.savePanel, BorderLayout.PAGE_END)

        self._splitpane.setBottomComponent(self._bottomPanel)

        callbacks.customizeUiComponent(self._splitpane)

        callbacks.addSuiteTab(self)
        
        print "Burp SSL Scanner loaded"

        self.scannerMenu = ScannerMenu(self)
        callbacks.registerContextMenuFactory(self.scannerMenu)
        print "SSL Scanner custom menu loaded"

        #print os.popen("openssl version").read()

        print 'Done'

        #print 'SSL VERSION: '+ssl.OPENSSL_VERSION
        
    def startScan(self, ev) :

        host = self.hostField.text
        self.scanningEvent.set()
        if(len(host) == 0):
            return 

        # try:
        print("Start scanning "+host)
        self.scannerThread = Thread(target=self.scan, args=(host, ))
        self.scannerThread.start()

        # except:
        #     print("Something wrong")

    def scan(self, host):
        res = result.Result()
        try :
            SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("Checking for supported SSL/TLS versions",)))
            con = connection_test.ConnectionTest(res, host, 443)
            con.start()

            SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("Checking for Heartbleed",)))
            heartbleed = heartbleed_test.HeartbleedTest(res, host, 443)
            heartbleed.start()

            SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("Checking for CCS Injection",)))
            ccs = ccs_test.CCSTest(res, host, 443)
            ccs.start()

            SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("Checking for TLS_FALLBACK_SCSV",)))
            fallback = fallback_test.FallbackTest(res, host, 443)
            fallback.start()

            SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("Checking for POODLE (SSLv3)",)))
            poodle = poodle_test.PoodleTest(res, host, 443)
            poodle.start()
            
            SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("Checking for SWEET32",)))
            sweet32 = sweet32_test.Sweet32Test(res, host, 443)
            sweet32.start()
            
            SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("Checking for DROWN",)))
            drown = drown_test.DrownTest(res, host, 443)
            drown.start()
            
            SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("Checking for FREAK",)))
            freak = freak_test.FreakTest(res, host, 443)
            freak.start()

        except BaseException as e :
            SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("An error occurred. Please refer to the errors tab for more information.",)))
            time.sleep(1)
            print(e)

        self.scanningEvent.clear()
        SwingUtilities.invokeLater(
                ScannerRunnable(self.scanStatusLabel.setText, 
                                ("Ready to scan",)))
        print("Finished scanning")

    def saveToFile(self, event):
        fileChooser = JFileChooser()
        if (fileChooser.showSaveDialog(self.getUiComponent()) == JFileChooser.APPROVE_OPTION):
            fw = FileWriter(fileChooser.getSelectedFile())
            fw.write(self._helpers.bytesToString(self.textEditorInstance.getText()))
            fw.flush()
            fw.close()
            print "Saved"

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

class ScannerRunnable(Runnable):
    def __init__(self, func, args):
        self.func = func
        self.args = args

    def run(self):
        self.func(*self.args)