'''
For each test entry, refer to the following example
for the details regarding each field.

POSSIBLE_TESTS = {
    'test_keyword': {
        'internalType' -> a unique number for the test
        'name' -> the name of the test
        'result' -> the descriptions for the test results (in the form of [False (0), True (1), others...(2, 3, 4, ...)] )
        'severity' -> the severity of the issue (High/Medium/Low/Information/False positive)
        'confidence' -> the issue confidence level (Certain/Firm/Tentative)
        'issueBackground' -> the background information for the issue (nullable)
        'remediationBackground' -> the background remediation for the issue (nullable)
    } 
}

Note: Some fields required to fully implement the IScanIssue interface
are purposely left out, as they are specific to a particular instance of the issue.
They are as follows:
    - url -> the url that is being tested
    - issue and remediation detail -> the additional descriptions for this specifc instance
    of the issue
    - HttpService -> the specific HTTP service for which the issue was generated
'''

POSSIBLE_TESTS = {
    'connectable': {
        'internalType': 0,
        'name': 'SSL/TLS Connection Test',
        'result': ['<b style="color: red;">Failed</b>', '<b style="color: green;">Successful</b>'],
    },
    'offer_ssl2': {
        'internalType': 1,
        'name': 'Offer SSLv2',
        'result': ['<b style="color: green;">No</b>', '<b style="color: red;">Yes (not OK)</b>'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': \
            ("The host uses SSLv2, which is a weak encryption scheme. "
             "<a href='https://cwe.mitre.org/data/definitions/326.html'>(CWE-326)</a>"),
        'remediationBackground': \
            ("SSLv2 should never be enabled on production systems.")
    },
    'offer_ssl3': {
        'internalType': 2,
        'name': 'Offer SSLv3',
        'result': ['<b style="color: green;">No</b>', '<b style="color: red;">Yes (not OK)</b>'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': \
            ("The host uses SSLv3, which is a weak encryption scheme broken by the POODLE attack. "
             "<a href='https://cwe.mitre.org/data/definitions/326.html'>(CWE-326)</a>"),
        'remediationBackground': \
            ("SSLv3 should never be enabled on production systems.")
    },
    'offer_tls10' : {
        'internalType': 3,
        'name': 'Offer TLS1.0',
        'result': ['No', 'Yes']
    },
    'offer_tls11' : {
        'internalType': 4,
        'name': 'Offer TLS1.1',
        'result': ['No', 'Yes']
    },
    'offer_tls12' : {
        'internalType': 5,
        'name': 'Offer TLS1.2',
        'result': ['No', '<b style="color: green;">Yes</b>']
    },
    'heartbleed': {
        'internalType': 6,
        'name': 'Heartbleed',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: red;">Vulnerable</b>'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': \
            ("The host is vulnerable to the HeartBleed vulnerability, "
             "which exposes the memory content of the host, allowing "
             "credentials to be stolen. "
             "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-0160'>(CVE-2014-0160)</a>"),
        'remediationBackground': \
            ("Update OpenSSL to version 1.0.1g or higher")
    },
    'ccs_injection': {
        'internalType': 7,
        'name': 'CCS Injection',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: red;">Vulnerable</b>'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': \
            ("The host is vulnerable to the CCS Injection vulnerability, "
             "which allows malicious intermediate nodes to intercept "
             "encrypted data and decrypt them while forcing SSL clients "
             "to use weak keys which are exposed to malicious nodes. "
             "<a href='http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224'>(CVE-2014-0224)</a>"),
        'remediationBackground': \
            ("Update OpenSSL to version 1.0.1h or higher")
    },
    'fallback_support': {
        'internalType': 8,
        'name': 'TLS_FALLBACK_SCSV Support',
        'result': ['<b style="color: red;">No</b>', '<b style="color: green;">Yes</b>'],
        'severity': 'Medium',
        'confidence': 'Certain',
        'issueBackground': \
            ("The host does not support the TLS_FALLBACK_SCSV flag "
             "which protects the connection from being downgraded "
             "to weaker encryptions, such as SSLv3. "
             "<a href='https://tools.ietf.org/html/rfc7507'>(RFC7507)</a>"),
        'remediationBackground': \
            ("If OpenSSL is used, update to version 1.0.1j or higher. "
             "Otherwise, update the web server and client to the latest version.")
    },
    'poodle_ssl3': {
        'internalType': 9,
        'name': 'POODLE (SSLv3)',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: red;">Vulnerable</b>'],
        'severity': 'High',
        'confidence': 'Tentative',
        'issueBackground': \
            ("The host is vulnerable to the POODLE attack "
             "which affects every website that supports SSLv3. "
             "The POODLE attack allows an attacker to extract "
             "the plaintext message of a targeted part of a request. "
             "There is also a variant of the attack that affects more "
             "recent versions of TLS. (Requires external tools) "
             "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566'>(CVE-2014-3566)</a>"),
        'remediationBackground': \
            ("If OpenSSL is used, update to version 1.0.1j or higher. "
             "Otherwise, update the web server and client to the latest version. "
             "Check for TLS_FALLBACK_SCSV support on the server to prevent downgrade attack and help mitigate this issue "
             "(SSL Scanner will report if there is no support for TLS_FALLBACK_SCSV). "
             "<b>Also, SSLv3 should never be offered.</b> "
             "<ul><li>For <b>Internet Explorer 6</b>, there is an option to <b>disable SSLv3 and "
             "enable TLS1.0</b>. However, it is only advisable as a <b>workaround.</b></li></ul>"),
    },
    'sweet32': {
        'internalType': 10,
        'name': 'Sweet32',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: red;">Vulnerable</b>'],
        'severity': 'Medium',
        'confidence': 'Firm',
        'issueBackground': \
            ("This server offers ciphers with block size of 64 bits which "
            "is vulnerable to birthday attack using reasonable amount "
            "of captured traffic. "
            "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2183'>(CVE-2016-2183)</a>"),
        'remediationBackground': \
            'Disable cipher with 64-bit block size (3DES, DES, Blowfish).'
    },
    'drown': {
        'internalType': 11,
        'name': 'DROWN',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: red;">Vulnerable</b>'],
        'severity': 'Medium',
        'confidence': 'Firm',
        'issueBackground': \
            ("The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g "
            "and other products, requires a server to send a "
            "ServerVerify message before establishing that a client possesses " 
            "certain plaintext RSA data, which makes it easier for remote attackers " 
            "to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding. "
            "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800'>(CVE-2016-0800)</a>"),
        'remediationBackground': \
            "Disable SSLv2 on the server. Do not reuse the certificate on SSLv2 hosts."
    },
    'freak': {
        'internalType': 12,
        'name': 'FREAK',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: red;">Vulnerable</b>'],
        'severity': 'Medium',
        'confidence': 'Firm',
        'issueBackground': \
            ("The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8zd, "
            "1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote SSL servers to conduct "
            "RSA-to-EXPORT_RSA downgrade attacks and facilitate brute-force decryption by offering "
            "a weak ephemeral RSA key in a noncompliant role. "
            "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0204'>(CVE-2015-0204)</a>"), 
        'remediationBackground': \
            "Disable support for TLS export cipher suites and/or upgrade OpenSSL."
    },
    'lucky13' : {
        'internalType': 13,
        'name': 'LUCKY13',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: orange;">Potentially vulnerable</b>'],
        'severity': 'Low',
        'confidence': 'Tentative',
        'issueBackground': \
            ("This server offers ciphers with CBC mode of operation. Some implementation do not " 
            "properly consider timing side-channel attack on a MAC check requirement. "
            "Please check if the version of the software is vulnerable to LUCKY13 or not. " 
            "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-0169'>(CVE-2013-0169)</a>"), 
        'remediationBackground': \
            "Check the server version and update to the latest version."
    },
    'crime_tls' : {
        'internalType': 14,
        'name': 'CRIME (TLS)',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: red;">Vulnerable</b>'],
        'severity': 'Low',
        'confidence': 'Certain',
        'issueBackground': \
            ("This server offers TLS compression which can lead to chosen plaintext attack where "
            "the attack can recover secret cookie such as authentication cookie using the size "
            "of compressed request/response. "
            "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-4929'>(CVE-2012-4929)</a>"), 
        'remediationBackground': \
            "Disable TLS compression on the server."
    },
    'breach' : {
        'internalType': 15,
        'name': 'BREACH',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: orange;">Potentially vulnerable</b>'],
        'severity': 'Medium',
        'confidence': 'Tentative',
        'issueBackground': \
            ("This server offers HTTP compression which can lead to chosen plaintext attack similar to CRIME where "
            "the attack can recover secret cookie such as authentication cookie using the size "
            "of compressed request/response. "
            "This issue can be ignored if there is no secret in the page or static pages."), 

        'remediationBackground': \
            ("Disable HTTP compression on the server or ignored if there is no secret in the page."), 
    },
    'cipher_NULL' : {
        'internalType': 16,
        'name': 'NULL Cipher (no encryption)',
        'result': ['<b style="color: green;">No</b>', '<b style="color: red;">Yes (not OK)</b>'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': 'This server offers null ciphers which does not encrypt the data at all',
        'remediationBackground': 'Disable null ciphers on the server.'
    },
    'cipher_ANON' : {
        'internalType': 17,
        'name': 'ANON Cipher (no authentication)',
        'result': ['<b style="color: green;">No</b>', '<b style="color: red;">Yes (not OK)</b>'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': 'This server offers anonymous ciphers which can lead to Man in the Middle attack',
        'remediationBackground': 'Disable anonymous ciphers on the server.'
    },
    'cipher_EXP' : {
        'internalType': 18,
        'name': 'EXP Cipher (without ADH+NULL)',
        'result': ['<b style="color: green;">No</b>', '<b style="color: red;">Yes (not OK)</b>'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': 'This server offers export ciphers which is insecure.',
        'remediationBackground': 'Disable export ciphers on the server.'
    },
    'cipher_LOW' : {
        'internalType': 19,
        'name': 'LOW Cipher (64 Bit + DES Encryption)',
        'result': ['<b style="color: green;">No</b>', '<b style="color: red;">Yes (not OK)</b>'],
        'severity': 'Medium',
        'confidence': 'Certain',
        'issueBackground': 'This server offers low strength ciphers (64 bit + DES).',
        'remediationBackground': 'Disable low strength ciphers (64 bit + DES) on the server.'
    },
    'cipher_WEAK' : {
        'internalType': 20,
        'name': 'WEAK Cipher (SEED, IDEA, RC2, RC4)',
        'result': ['<b style="color: green;">No</b>', '<b style="color: red;">Yes (not OK)</b>'],
        'severity': 'Medium',
        'confidence': 'Certain',
        'issueBackground': 'This server offers weak ciphers (SEED, IDEA, RC2, RC4).',
        'remediationBackground': 'Disable weak ciphers (SEED, IDEA, RC2, RC4) on the server.'
    },
    'cipher_3DES' : { # Not recommended
        'internalType': 21,
        'name': '3DES Cipher (Medium)',
        'result': ['<b style="color: green;">No</b>', '<b style="color: orange;">Yes (not recommended)</b>'],
        'severity': 'Information',
        'confidence': 'Certain',
        'issueBackground': 'This server offers 3DES ciphers which are prone to birthday attack (Sweet32).',
        'remediationBackground': 'Disable 3DES ciphers on the server.'
    },
    'cipher_HIGH' : { # Not an issue
        'internalType': 22,
        'name': 'HIGH Cipher (AES+Camellia, no AEAD)',
        'result': ['<b style="color: red;">No (not OK)</b>', '<b style="color: green;">Yes (OK)</b>']
    },
    'cipher_STRONG' : { # Not an issue
        'internalType': 23,
        'name': 'STRONG Cipher (AEAD Ciphers)',
        'result': ['<b style="color: red;">No (not OK)</b>', '<b style="color: green;">Yes (OK)</b>'],
    },
    'beast' : {
        'internalType': 24,
        'name': 'BEAST',
        'result': [
            '<b style="color: green;">Not vulnerable</b>', 
            '<b style="color: green;">Vulnerable (but also supports higher protocols, likely mitigated)</b>', 
            '<b style="color: red;">Vulnerable</b>'],
        'severity': 'Medium',
        'confidence': 'Tentative',
        'issueBackground': \
            ("This server offers CBC ciphers with SSLv3 or TLS1.0. "
            "which allows man-in-the-middle attackers to obtain plaintext HTTP headers "
            "via a blockwise chosen-boundary attack (BCBA) on an HTTPS session. "
            "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3389'>(CVE-2011-3389)</a>"), 
        'remediationBackground': \
            ("Disable SSLv3 and TLS1.0 if possible. "
            "Check for TLS_FALLBACK_SCSV support to prevent downgrade attack."
            "Disable CBC ciphers and use more secure ciphers that are supported in higher protocol.")
    },
    'supported_ciphers' : {
        'internalType': 25,
        'name': 'Supported Cipher Suites',
        'result': ['', ''],
        'severity': 'Information',
        'confidence': 'Firm',
        'issueBackground': None,
        'remediationBackground': None
    },
    'logjam_export' : {
        'internalType': 26,
        'name': 'LOGJAM (Export)',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: red;">Vulnerable</b>'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': \
            ("This server offers DHE_EXPORT cipher which is insecure. "),
        'remediationBackground': \
            ("Disable DHE_EXPORT cipher. ")
    },
    'logjam_common' : {
        'internalType': 27,
        'name': 'LOGJAM (Common Prime)',
        'result': ['<b style="color: green;">Not vulnerable</b>', '<b style="color: red;">Vulnerable</b>'],
        'severity': 'Medium',
        'confidence': 'Certain',
        'issueBackground': \
            ("This server offers Diffie-Hellman key exchange with common prime number whose size is 1024-bit or less. "
            "Attackers can do precomputation using only this prime to quickly break individual connections. "
            "It is suspected that the prime can be broken by nation-level agencies. "), 
        'remediationBackground': \
            ("Configure the server to use a 2048-bit Diffie-Hellman group. ")
    }
}


# Text to print for each scan accuracy setting
SCANNING_ACCURACY_INFO = {
    'minimise_false_negatives' : 
        '''
        <ul>
            <li><b>[LUCKY13]</b> Vulnerability will not be reported on the cipher list and scanner issue because \
            the test couldn't determined if the server was patched or not.</li>
        </ul>
        ''',
    'normal' : '',
    'minimise_false_positives' : ''
}


# Text to print for each scan speed setting
SCANNING_SPEED_INFO = {
    'fast' : '',
    'normal' : '',
    'thorough' : ''
}