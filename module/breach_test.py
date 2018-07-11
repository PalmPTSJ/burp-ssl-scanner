

class BreachTest :
    def __init__(self, result, host, port) :
        self._result = result
        self._host = host
        self._port = port
    
    def testPage(self, page, callback, helpers, depth) :
        if depth >= 10 :
            print("Too many redirection ...")
            return False

        print("Getting", page)

        request = 'GET %s HTTP/1.1\r\n' % page
        request += 'Host: %s\r\n' % self._host

        if 'google' in self._host : 
            referer = 'https://yandex.ru/'
        else : 
            referer = 'https://google.com/'

        request += 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n'
        request += 'Referer: %s\r\n' % referer
        request += 'Connection: Close\r\nAccept-encoding: gzip,deflate,compress\r\nAccept: text/*\r\n\r\n'

        print request

        res = callback.makeHttpRequest(self._host, self._port, True, helpers.stringToBytes(request))
        res = helpers.analyzeResponse(res)

        print res.getHeaders()
        if res.getStatusCode() == 302 :
            # Follow redirection
            for header in res.getHeaders() :
                if len(header) <= 10 : continue
                headerLowercase = str(header.lower())
                if headerLowercase.find('location: ') == 0 :
                    return self.testPage(header[10:], callback, helpers, depth+1)
            print("Can't find redirection")
            return False
        else :
            for header in res.getHeaders() :
                if len(header) <= 18 : continue
                headerLowercase = str(header.lower())
                if headerLowercase.find('Content-Encoding: ') == 0 :
                    return True
        return False

    def start(self, callback, helpers) : # Need HTTP service from Burp

        self._result.addResult('breach', self.testPage('/', callback, helpers, 0))
        if self._result.getResult('breach') :
            # Use HTTP Compression
            self._result.addVulnerability('breach')

