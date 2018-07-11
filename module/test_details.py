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
        'internalType': 0
        'name': 'SSL/TLS Connection Test',
        'result': ['Failed', 'Successful'],
        'type': 0x08000000,
        'severity': 'Information',
        'confidence': 'Certain',
        'issueBackground': None,
        'remediationBackground': None,
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