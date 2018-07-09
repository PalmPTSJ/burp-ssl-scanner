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

    import result
    import connection_test
    import heartbleed_test
    import ccs_test
    import fallback_test
    import poodle_test
    
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

        self._splitpane.setTopComponent(self._topPanel)

        callbacks.customizeUiComponent(self._splitpane)

        callbacks.addSuiteTab(self)
        
        print "Burp SSL Explorer loaded"
        
        #print os.popen("openssl version").read()

        print 'Done'

        #print 'SSL VERSION: '+ssl.OPENSSL_VERSION
        
    def startScan(self, ev) :

        host = self.hostField.text

        print("Start scanning "+host)

        '''
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
        if offer_tls12 :
            if heartbleed_test.test_heartbleed(host,443,3) :
                print("[CRITICAL] Heartbleed success (TLS 1.2)")
            else :
                print("Heartbleed not found (TLS 1.2)")
        elif offer_tls11 :
            if heartbleed_test.test_heartbleed(host,443,2) :
                print("[CRITICAL] Heartbleed success (TLS 1.1)")
            else :
                print("Heartbleed not found (TLS 1.1)")
        elif offer_tls10 :
            if heartbleed_test.test_heartbleed(host,443,1) :
                print("[CRITICAL] Heartbleed success (TLS 1.0)")
            else :
                print("Heartbleed not found (TLS 1.0)")
        else :
            print("TLS Not supported for testing Heartbleed")

        # CCS
        if ccs_test.test_ccs(host,443) :
            print("[CRITICAL] CCS Injection")
        else :
            print("CCS Injection not found")

        # Test for TLS_FALLBACK_SCSV

        fallback_scsv_to_ssl3 = '160300009c010000980300b8cd74dbfed2e4c86f90d130f07421f8d33da498d35ca56370f88d51373c26b4000070c014c00a00390038003700360088008700860085c00fc005003500840095c013c0090033003200310030009a0099009800970045004400430042c00ec004002f0096004100070094c011c0070066c00cc002000500040092c012c008001600130010000dc00dc003000a009300ff5600020100'
        '''


        res = result.Result()

        con = connection_test.ConnectionTest(res, host, 443)
        con.start()

        heartbleed = heartbleed_test.HeartbleedTest(res, host, 443)
        heartbleed.start()

        ccs = ccs_test.CCSTest(res, host, 443)
        ccs.start()

        fallback = fallback_test.FallbackTest(res, host, 443)
        fallback.start()

        poodle = poodle_test.PoodleTest(res, host, 443)
        poodle.start()

        print("Finished scanning")

    def getTabCaption(self):
        return "SSL Scanner"

    def getUiComponent(self):
        return self._splitpane