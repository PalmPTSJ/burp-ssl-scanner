'''
For each test entry, refer to the following example
for the details regarding each field.

POSSIBLE_TESTS = {
    'test_keyword': {
        'internalType' -> a unique number for the test
        'name' -> the name of the test
        'result' -> the descriptions for the test results (in the form of [False, True])
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
        'result': ['Failed', 'Successful'],
    },
    'offer_ssl2': {
        'internalType': 1,
        'name': 'Offer SSLv2',
        'result': ['No', 'Yes (not OK)'],
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
        'result': ['No', 'Yes (not OK)'],
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
        'result': ['No', 'Yes']
    },
    'heartbleed': {
        'internalType': 6,
        'name': 'Heartbleed',
        'result': ['Not vulnerable', 'Vulnerable'],
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
        'result': ['Not vulnerable', 'Vulnerable'],
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
        'result': ['No', 'Yes'],
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
        'result': ['Not vulnerable', 'Vulnerable'],
        'severity': 'High',
        'confidence': 'Certain',
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
             "Also, SSLv3 should never be offered.")
    },
    'sweet32': {
        'name': 'SWEET32',
        'result': ['Not vulnerable', 'Potentially vulnerable']
    },
    'drown': {
        'name': 'DROWN',
        'result': ['Not vulnerable', 'Vulnerable']
    },
    'freak': {
        'name': 'FREAK',
        'result': ['Not vulnerable', 'Vulnerable']
    },
    'lucky13' : {
        'name': 'LUCKY13',
        'result': ['Not vulnerable', 'Potentially vulnerable']
    },
    'crime_tls' : {
        'name': 'CRIME (TLS)',
        'result': ['Not vulnerable', 'Vulnerable']
    },
    'breach' : {
        'name': 'BREACH',
        'result': ['Not vulnerable', 'Vulnerable']
    },
    'cipher_NULL' : {
        'name': 'NULL Cipher (no encryption)',
        'result': ['No', 'Yes (not OK)']
    },
    'cipher_ANON' : {
        'name': 'ANON Cipher (no authentication)',
        'result': ['No', 'Yes (not OK)']
    },
    'cipher_EXP' : {
        'name': 'EXP Cipher (without ADH+NULL)',
        'result': ['No', 'Yes (not OK)']
    },
    'cipher_LOW' : {
        'name': 'LOW Cipher (64 Bit + DES Encryption)',
        'result': ['No', 'Yes (not OK)']
    },
    'cipher_WEAK' : {
        'name': 'WEAK Cipher (SEED, IDEA, RC2, RC4)',
        'result': ['No', 'Yes (not OK)']
    },
    'cipher_3DES' : {
        'name': '3DES Cipher (Medium)',
        'result': ['No', 'Yes (not recommended)']
    },
    'cipher_HIGH' : {
        'name': 'HIGH Cipher (AES+Camellia, no AEAD)',
        'result': ['No', 'Yes']
    },
    'cipher_STRONG' : {
        'name': 'STRONG Cipher (AEAD Ciphers)',
        'result': ['No', 'Yes']
    }
}