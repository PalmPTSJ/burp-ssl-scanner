try:
    from burp import IBurpExtender
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import ITab
    from burp import IMessageEditor
    from burp import IContextMenuFactory
    from burp import IContextMenuInvocation
    from burp import IHttpRequestResponse
    # from burp import IScanIssue
    # from array import array
    # from time import sleep
    from java.io import PrintWriter
    from java.lang import Runnable
    from javax.swing import (JTable, JScrollPane, JSplitPane, JButton, JPanel,
                             JTextField, JLabel, SwingConstants, JDialog, Box,
                             JCheckBox, JMenuItem, SwingUtilities, JOptionPane,
                             BoxLayout, JPopupMenu)

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

    #sys.path.append(os.path.dirname(os.path.realpath('testselenium.jar')) + '/testselenium.jar')

    #from testselenium import Test

    import re
    import hashlib

    import ssl

    import result
    import connection_test
    import heartbleed_test
    import ccs_test
    
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
        self.crawlStatusPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))

        self.crawlStatusPanel.add(JLabel("Status: ", SwingConstants.LEFT))

        self.crawlStatusLabel = JLabel("Ready to scan", SwingConstants.LEFT)
        self.crawlStatusPanel.add(self.crawlStatusLabel)

        self._topPanel.add(self.crawlStatusPanel, BorderLayout.LINE_START)

        self._splitpane.setTopComponent(self._topPanel)

        # bottom panel 
        self._bottomPanel = JPanel(BorderLayout(10, 10))
        self._bottomPanel.setBorder(EmptyBorder(10, 0, 0, 0))

        self.textEditorInstance = callbacks.createTextEditor()
        self.textEditorInstance.setEditable(False)
        initialText = 'Press "Start scanning" to get started'
        self.textEditorInstance.setText(self._helpers.stringToBytes(initialText))
        self._bottomPanel.add(self.textEditorInstance.getComponent(), BorderLayout.CENTER)

        self.savePanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.savePanel.add(JButton('Save to file', actionPerformed=self.saveToFile))
        self._bottomPanel.add(self.savePanel, BorderLayout.PAGE_END)

        self._splitpane.setBottomComponent(self._bottomPanel)

        callbacks.customizeUiComponent(self._splitpane)

        callbacks.addSuiteTab(self)
        
        print "Burp SSL Explorer loaded"
        
        #print os.popen("openssl version").read()

        print 'Done'

        #print 'SSL VERSION: '+ssl.OPENSSL_VERSION
        
    def startScan(self, ev) :

        host = self.hostField.text
        if(len(host) == 0):
            return 

        try:
            print("Start scanning "+host)

            res = result.Result()

            con = connection_test.ConnectionTest(res, host, 443)
            con.start()

            heartbleed = heartbleed_test.HeartbleedTest(res, host, 443)
            heartbleed.start()

            ccs = ccs_test.CCSTest(res, host, 443)
            ccs.start()
        except:
            print("Something wrong")
        

        print("Finished scanning")

    def saveToFile(self):
        print "Saved"

    def getTabCaption(self):
        return "SSL Scanner"

    def getUiComponent(self):
        return self._splitpane
    