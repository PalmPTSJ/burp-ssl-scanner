'''
For each test entry, refer to the following example
for the details regarding each field.

POSSIBLE_TESTS = {
    'test_keyword': {
        'internalType' -> a unique number for the test
        'name' -> the name of the test
        'result' -> the descriptions for the test results (in the form of [False, True])
        'type' -> the specific Burp Issue Index type of this vulnerability/issue (0x08000000)
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
        'type': 0x08000000,
    },
    'offer_ssl2': {
        'name': 'Offer SSLv2',
        'result': ['No', 'Yes (not OK)']
    },
    'offer_ssl3': {
        'name': 'Offer SSLv3',
        'result': ['No', 'Yes (not OK)']
    },
    'offer_tls10' : {
        'name': 'Offer TLS1.0',
        'result': ['No', 'Yes']
    },
    'offer_tls11' : {
        'name': 'Offer TLS1.1',
        'result': ['No', 'Yes']
    },
    'offer_tls12' : {
        'name': 'Offer TLS1.2',
        'result': ['No', 'Yes']
    },
    'heartbleed': {
        'name': 'Heartbleed',
        'result': ['Not vulnerable', 'Vulnerable']
    },
    'ccs_injection': {
        'name': 'CCS Injection',
        'result': ['Not vulnerable', 'Vulnerable']
    },
    'fallback_support': {
        'name': 'TLS_FALLBACK_SCSV Support',
        'result': ['No', 'Yes']
    },
    'poodle_ssl3': {
        'name': 'POODLE (SSLv3)',
        'result': ['Not vulnerable', 'Vulnerable']
    },
    'sweet32': {
        'internalType': 10,
        'name': 'Sweet32',
        'result': ['Not vulnerable', 'Potentially vulnerable'],
        'severity': 'Medium',
        'confidence': 'Firm',
        'issueBackground': \
            ("Server offer ciphers with block size of 64 bits which "
            "is vulnerable to birthday attack using reasonable amount "
            "of captured traffic. "
            "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2183'>(CVE-2016-2183)</a>"),
        'remediationBackground': \
            'Disable cipher with 64-bit block size (3DES, DES, Blowfish).'
    },
    'drown': {
        'internalType': 11,
        'name': 'DROWN',
        'result': ['Not vulnerable', 'Vulnerable'],
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
        'result': ['Not vulnerable', 'Vulnerable'],
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
        'result': ['Not vulnerable', 'Potentially vulnerable'],
        'severity': 'Low',
        'confidence': 'Tentative',
        'issueBackground': \
            ("Server offer ciphers with CBC mode of operation. Some implementation do not " 
            "properly consider timing side-channel attack on a MAC check requirement. "
            "Please check if the version of the software is vulnerable to LUCKY13 or not. " 
            "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-0169'>(CVE-2013-0169)</a>"), 
        'remediationBackground': \
            "Check the server version and update to the latest version."
    },
    'crime_tls' : {
        'internalType': 14,
        'name': 'CRIME (TLS)',
        'result': ['Not vulnerable', 'Vulnerable'],
        'severity': 'Low',
        'confidence': 'Certain',
        'issueBackground': \
            ("Server offer TLS compression which can lead to chosen plaintext attack where "
            "the attack can recover secret cookie such as authentication cookie using the size "
            "of compressed request/response. "
            "<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-4929'>(CVE-2012-4929)</a>"), 
        'remediationBackground': \
            "Disable TLS compression on the server."
    },
    'breach' : {
        'internalType': 15,
        'name': 'BREACH',
        'result': ['Not vulnerable', 'Vulnerable']
    },
    'cipher_NULL' : {
        'internalType': 16,
        'name': 'NULL Cipher (no encryption)',
        'result': ['No', 'Yes (not OK)'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': 'Server offer null ciphers which does not encrypt the data at all',
        'remediationBackground': 'Disable null ciphers on the server.'
    },
    'cipher_ANON' : {
        'internalType': 17,
        'name': 'ANON Cipher (no authentication)',
        'result': ['No', 'Yes (not OK)'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': 'Server offer anonymous ciphers which can lead to Man in the Middle attack',
        'remediationBackground': 'Disable anonymous ciphers on the server.'
    },
    'cipher_EXP' : {
        'internalType': 18,
        'name': 'EXP Cipher (without ADH+NULL)',
        'result': ['No', 'Yes (not OK)'],
        'severity': 'High',
        'confidence': 'Certain',
        'issueBackground': 'Server offer export ciphers which is insecure.',
        'remediationBackground': 'Disable export ciphers on the server.'
    },
    'cipher_LOW' : {
        'internalType': 19,
        'name': 'LOW Cipher (64 Bit + DES Encryption)',
        'result': ['No', 'Yes (not OK)'],
        'severity': 'Medium',
        'confidence': 'Certain',
        'issueBackground': 'Server offer low strength ciphers (64 bit + DES).',
        'remediationBackground': 'Disable low strength ciphers (64 bit + DES) on the server.'
    },
    'cipher_WEAK' : {
        'internalType': 20,
        'name': 'WEAK Cipher (SEED, IDEA, RC2, RC4)',
        'result': ['No', 'Yes (not OK)'],
        'severity': 'Medium',
        'confidence': 'Certain',
        'issueBackground': 'Server offer weak ciphers (SEED, IDEA, RC2, RC4).',
        'remediationBackground': 'Disable weak ciphers (SEED, IDEA, RC2, RC4) on the server.'
    },
    'cipher_3DES' : { # Not recommended
        'internalType': 21,
        'name': '3DES Cipher (Medium)',
        'result': ['No', 'Yes (not recommended)'],
        'severity': 'Information',
        'confidence': 'Certain',
        'issueBackground': 'Server offer 3DES ciphers which are prone to birthday attack (Sweet32).',
        'remediationBackground': 'Disable 3DES ciphers on the server.'
    },
    'cipher_HIGH' : { # Not an issue
        'internalType': 22,
        'name': 'HIGH Cipher (AES+Camellia, no AEAD)',
        'result': ['No', 'Yes']
    },
    'cipher_STRONG' : { # Not an issue
        'internalType': 23,
        'name': 'STRONG Cipher (AEAD Ciphers)',
        'result': ['No', 'Yes'],
    }
}