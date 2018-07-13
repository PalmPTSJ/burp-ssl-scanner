# Burp SSL Scanner

Burp Suite plugin for scanning SSL vulnerabilities.

_by [kheminw](https://github.com/kheminw) and [PalmPTSJ](https://github.com/PalmPTSJ)_

## Installing

- Launch Burp Suite
- Click the Extender tab
- Add the extension to your list while selecting Python as the language

## Vulnerabilities

- SSLv2 and SSLv3 connectivity
- Heartbleed
- CCS Injection
- TLS_FALLBACK_SCSV support
- POODLE (SSLv3)
- Sweet32
- DROWN
- FREAK
- LUCKY13
- CRIME (TLS Compression)
- BEAST
- Check for weak ciphers
- BREACH
- Logjam

## Credits

Most of the testing logic are from [testssl.sh](https://testssl.sh)

Heartbleed test and CCS Injection test code are modified from [a2sv](https://github.com/hahwul/a2sv)