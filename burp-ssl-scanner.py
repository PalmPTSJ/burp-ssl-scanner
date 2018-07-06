try:
    from burp import IBurpExtender
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import ITab
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
        self._callbacks.setExtensionName('Burp SSL Explorer')
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

        self._splitpane.setTopComponent(self._topPanel)

        callbacks.customizeUiComponent(self._splitpane)

        callbacks.addSuiteTab(self)
        
        print "Burp SSL Explorer loaded"
        
        #print os.popen("openssl version").read()

        print 'Done'

        print 'SSL VERSION: '+ssl.OPENSSL_VERSION
        
    def startScan(self, ev) :

        host = self.hostField.text

        print("Start scanning "+host)

        offer_ssl2, offer_ssl3, offer_tls10, offer_tls11, offer_tls12 = [False]*5

        if(connection_test.test_sslv2(host,443)) :
            offer_ssl2 = True
            print "[CRITICAL] SSLv2 offered"

        if(connection_test.test_sslv3(host,443)) :
            offer_ssl3 = True
            print "[HIGH] SSLv3 offered"
        
        if(connection_test.test_tls10(host,443)) :
            offer_tls10 = True
            print "TLSv1.0 offered"

        if(connection_test.test_tls11(host,443)) :
            offer_tls11 = True
            print "TLSv1.1 offered"

        if(connection_test.test_tls12(host,443)) :
            offer_tls12 = True
            print "TLSv1.2 offered"

        # Heartbleed
        if offer_tls10 :
            if heartbleed_test.test_heartbleed(host,443,1) :
                print("[CRITICAL] Heartbleed success (TLS 1.0)")
            else :
                print("Heartbleed not found (TLS 1.0)")
        elif offer_tls11 :
            if heartbleed_test.test_heartbleed(host,443,2) :
                print("[CRITICAL] Heartbleed success (TLS 1.1)")
            else :
                print("Heartbleed not found (TLS 1.1)")
        elif offer_tls12 :
            if heartbleed_test.test_heartbleed(host,443,3) :
                print("[CRITICAL] Heartbleed success (TLS 1.2)")
            else :
                print("Heartbleed not found (TLS 1.2)")
        else :
            print("TLS Not supported for testing Heartbleed")

        # CCS
        if ccs_test.test_ccs(host,443) :
            print("[CRITICAL] CCS Injection")
        else :
            print("CCS Injection not found")


        print("Finished scanning")

    def getTabCaption(self):
        return "SSL Explorer"

    def getUiComponent(self):
        return self._splitpane