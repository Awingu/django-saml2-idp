import string
import unittest
from saml2idp import xml_render
from saml2idp.xml_signing import get_signature_xml
from saml2idp.xml_templates import ASSERTION_SALESFORCE, RESPONSE

IDP_PARAMS = {
    'ISSUER': 'http://127.0.0.1:8000',
}

REQUEST_PARAMS = {
    'ACS_URL': 'https://www.example.net/a/example.com/acs',
    'REQUEST_ID': 'mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi',
}

ASSERTION_SALESFORCE_PARAMS = {
    'ASSERTION_ID': '_7ccdda8bc6b328570c03b218d7521772998da45374',
    'ASSERTION_SIGNATURE': '',  # it's unsigned
    'AUDIENCE': 'example.net',
    'AUTH_INSTANT': '2011-08-11T23:38:34Z',
    'ISSUE_INSTANT': '2011-08-11T23:38:34Z',
    'NOT_BEFORE': '2011-08-11T23:38:04Z',
    'NOT_ON_OR_AFTER': '2011-08-11T23:43:34Z',
    'SESSION_NOT_ON_OR_AFTER': '2011-08-12T07:38:34Z',
    'SP_NAME_QUALIFIER': 'example.net',
    'SUBJECT': 'randomuser@example.com',
    'SUBJECT_FORMAT': 'urn:oasis:names:tc:SAML:2.0:nameid-format:email',
}

ASSERTION_SALESFORCE_XML = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>'  # noqa
SIGNED_ASSERTION_SALESFORCE_XML = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_7ccdda8bc6b328570c03b218d7521772998da45374"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>j30szp/qr9wKdWdS6BIv3Lu7cBnNB1ZzeJXtBFk52ovY44htgkEwalwG47aoQBs8oHY3rNRGGCow4ZYQY3JejZeVBizneyywJS/FKkj7jhN6/f9S7m5XffyRxsY0k0igGp3dMbXmkokVC3MyN/DEVBjmma+nZIsNtGdCRBbEVWqTWnHvbcmYYbkmT2Ms3YhC8rDMV2uvkAZKsZFeQbQs/ewY3AVsozqPJ0xSadzmyj/FdGRciGEZMg6xw5qT+OjAPahmFgpECJQ6nUPGNTyXhbkHhrQWwQdsEyuyqoOA7JvvY73XAO1d1zFWtXUs2U21HewHvIBy4oEVzbv/8aS25Q==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDxzCCAq+gAwIBAgIJAPXQumUynZvpMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTAeFw0xNDA4MTkxMjUxNDlaFw0xNTA4MTkxMjUxNDlaMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPKQTRn0XoqhbNlBGFaSvjnHwd+zs0z3cpMZ6SnJy3bynaji06EQ31NFg5pd/XvUdElJv4HL2WE+CCY6R0mJADxk4vO9yuf0aw8sFqNoflUYgYfsO+LwIo+gWekb84F/X9qttiAH//c+WM5G9S+OEQV9Xff6lecdaW4ZKKmRyxgsAH7plp9BJbmQrfjoWrqCQZOj9uypc2n0MLoUpg3WQxiDF+4I/n6Kj9PWrG0cft5jZqoiWHwDuZB+OE9gESZR0eu6oyEnvO6E36Bd5Fs95/U7wnHLvY6xQdwQQS0h26l51Rn7UedizGv/c1TnsbQNP1T1GXJydZ02UAXLAmt84xkCAwEAAaNQME4wHQYDVR0OBBYEFFfiUW6cHTScWqymoG2HlsXp4NR9MB8GA1UdIwQYMBaAFFfiUW6cHTScWqymoG2HlsXp4NR9MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJJPxpn991yLvzbZft7G/SiLKvU41B7PqB5chtUfDDn+rMvs+Fmx5SoyMv00HrkrT+dVNLYV6mDclRtB7MbAFnMoQLqNGx7DR4o/JhI9bT6hnioogu7gkDeOBjwBwEy9Wm4TwAa0/QXjpsJW9uTvfZLOwD3oMh3YcEmAKRC+eyGYWE67/gTB4JKwmFyJj0e/LKAzZhZGEGdFnpHwLm6M9fRUQNWY4ykbK0hN46B2nc/3r2MMMo0JcwLEXNBO9Qs/hTh5pr2bmTcGnkJHJrnwiTOZxHCYlY8Fv3xMSkq1At5eZJuPqq0RjYtbldLukqrJ0DO4gWxFxy/KBrTeTsjhJl4=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>'  # noqa

RESPONSE_PARAMS = {
    'ASSERTION': '',
    'ISSUE_INSTANT': '2011-08-11T23:38:34Z',
    'NOT_ON_OR_AFTER': '2011-08-11T23:43:34Z',
    'RESPONSE_ID': '_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4',
    'RESPONSE_SIGNATURE': '',
    'SP_NAME_QUALIFIER': 'example.net',
    'SUBJECT': 'randomuser@example.com',
    'SUBJECT_FORMAT': 'urn:oasis:names:tc:SAML:2.0:nameid-format:email',
}

RESPONSE_XML = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://www.example.net/a/example.com/acs" ID="_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4" InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://127.0.0.1:8000</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>'  # noqa
RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://www.example.net/a/example.com/acs" ID="_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4" InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://127.0.0.1:8000</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_7ccdda8bc6b328570c03b218d7521772998da45374"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>j30szp/qr9wKdWdS6BIv3Lu7cBnNB1ZzeJXtBFk52ovY44htgkEwalwG47aoQBs8oHY3rNRGGCow4ZYQY3JejZeVBizneyywJS/FKkj7jhN6/f9S7m5XffyRxsY0k0igGp3dMbXmkokVC3MyN/DEVBjmma+nZIsNtGdCRBbEVWqTWnHvbcmYYbkmT2Ms3YhC8rDMV2uvkAZKsZFeQbQs/ewY3AVsozqPJ0xSadzmyj/FdGRciGEZMg6xw5qT+OjAPahmFgpECJQ6nUPGNTyXhbkHhrQWwQdsEyuyqoOA7JvvY73XAO1d1zFWtXUs2U21HewHvIBy4oEVzbv/8aS25Q==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDxzCCAq+gAwIBAgIJAPXQumUynZvpMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTAeFw0xNDA4MTkxMjUxNDlaFw0xNTA4MTkxMjUxNDlaMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPKQTRn0XoqhbNlBGFaSvjnHwd+zs0z3cpMZ6SnJy3bynaji06EQ31NFg5pd/XvUdElJv4HL2WE+CCY6R0mJADxk4vO9yuf0aw8sFqNoflUYgYfsO+LwIo+gWekb84F/X9qttiAH//c+WM5G9S+OEQV9Xff6lecdaW4ZKKmRyxgsAH7plp9BJbmQrfjoWrqCQZOj9uypc2n0MLoUpg3WQxiDF+4I/n6Kj9PWrG0cft5jZqoiWHwDuZB+OE9gESZR0eu6oyEnvO6E36Bd5Fs95/U7wnHLvY6xQdwQQS0h26l51Rn7UedizGv/c1TnsbQNP1T1GXJydZ02UAXLAmt84xkCAwEAAaNQME4wHQYDVR0OBBYEFFfiUW6cHTScWqymoG2HlsXp4NR9MB8GA1UdIwQYMBaAFFfiUW6cHTScWqymoG2HlsXp4NR9MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJJPxpn991yLvzbZft7G/SiLKvU41B7PqB5chtUfDDn+rMvs+Fmx5SoyMv00HrkrT+dVNLYV6mDclRtB7MbAFnMoQLqNGx7DR4o/JhI9bT6hnioogu7gkDeOBjwBwEy9Wm4TwAa0/QXjpsJW9uTvfZLOwD3oMh3YcEmAKRC+eyGYWE67/gTB4JKwmFyJj0e/LKAzZhZGEGdFnpHwLm6M9fRUQNWY4ykbK0hN46B2nc/3r2MMMo0JcwLEXNBO9Qs/hTh5pr2bmTcGnkJHJrnwiTOZxHCYlY8Fv3xMSkq1At5eZJuPqq0RjYtbldLukqrJ0DO4gWxFxy/KBrTeTsjhJl4=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>'  # noqa

SIGNED_RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://www.example.net/a/example.com/acs" ID="_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4" InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://127.0.0.1:8000</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>0tsGWWn5fSf3eimKbzUAg3Ns5F4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>1BcLL8sOfYrPUUdkZJhE+pSUTCAdn3lUjlRW56JbZN6WKgnxLTLHPg20SIN0jwvsZ9mYfxE5UkMtXzkOdmaCxnBdA4mUE2GSnmj9S+K8AKd9W6ppVzj7tYwKIOeF2iXFQJJ08mxH/PB2C2vw3wmVDkd23Ipzey0rvV5X3csgD5uhLJihA8gQp4zwuBjg1X2DWvyPd1gfTiDy8BW1PkSaZu40Q7LlPkyvof2DHtwG+YaQffOIYsweBtkduVe02W+zMtKWbxR8kgrYvi+JBNcH4R+i0t5UTonkvaTUUKu/kwc9prMNJFGMMw8b1qKIdKGaVcC2o5aB/Xs32KhjBGNAOg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDxzCCAq+gAwIBAgIJAPXQumUynZvpMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTAeFw0xNDA4MTkxMjUxNDlaFw0xNTA4MTkxMjUxNDlaMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPKQTRn0XoqhbNlBGFaSvjnHwd+zs0z3cpMZ6SnJy3bynaji06EQ31NFg5pd/XvUdElJv4HL2WE+CCY6R0mJADxk4vO9yuf0aw8sFqNoflUYgYfsO+LwIo+gWekb84F/X9qttiAH//c+WM5G9S+OEQV9Xff6lecdaW4ZKKmRyxgsAH7plp9BJbmQrfjoWrqCQZOj9uypc2n0MLoUpg3WQxiDF+4I/n6Kj9PWrG0cft5jZqoiWHwDuZB+OE9gESZR0eu6oyEnvO6E36Bd5Fs95/U7wnHLvY6xQdwQQS0h26l51Rn7UedizGv/c1TnsbQNP1T1GXJydZ02UAXLAmt84xkCAwEAAaNQME4wHQYDVR0OBBYEFFfiUW6cHTScWqymoG2HlsXp4NR9MB8GA1UdIwQYMBaAFFfiUW6cHTScWqymoG2HlsXp4NR9MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJJPxpn991yLvzbZft7G/SiLKvU41B7PqB5chtUfDDn+rMvs+Fmx5SoyMv00HrkrT+dVNLYV6mDclRtB7MbAFnMoQLqNGx7DR4o/JhI9bT6hnioogu7gkDeOBjwBwEy9Wm4TwAa0/QXjpsJW9uTvfZLOwD3oMh3YcEmAKRC+eyGYWE67/gTB4JKwmFyJj0e/LKAzZhZGEGdFnpHwLm6M9fRUQNWY4ykbK0hN46B2nc/3r2MMMo0JcwLEXNBO9Qs/hTh5pr2bmTcGnkJHJrnwiTOZxHCYlY8Fv3xMSkq1At5eZJuPqq0RjYtbldLukqrJ0DO4gWxFxy/KBrTeTsjhJl4=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_7ccdda8bc6b328570c03b218d7521772998da45374"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>j30szp/qr9wKdWdS6BIv3Lu7cBnNB1ZzeJXtBFk52ovY44htgkEwalwG47aoQBs8oHY3rNRGGCow4ZYQY3JejZeVBizneyywJS/FKkj7jhN6/f9S7m5XffyRxsY0k0igGp3dMbXmkokVC3MyN/DEVBjmma+nZIsNtGdCRBbEVWqTWnHvbcmYYbkmT2Ms3YhC8rDMV2uvkAZKsZFeQbQs/ewY3AVsozqPJ0xSadzmyj/FdGRciGEZMg6xw5qT+OjAPahmFgpECJQ6nUPGNTyXhbkHhrQWwQdsEyuyqoOA7JvvY73XAO1d1zFWtXUs2U21HewHvIBy4oEVzbv/8aS25Q==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDxzCCAq+gAwIBAgIJAPXQumUynZvpMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTAeFw0xNDA4MTkxMjUxNDlaFw0xNTA4MTkxMjUxNDlaMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPKQTRn0XoqhbNlBGFaSvjnHwd+zs0z3cpMZ6SnJy3bynaji06EQ31NFg5pd/XvUdElJv4HL2WE+CCY6R0mJADxk4vO9yuf0aw8sFqNoflUYgYfsO+LwIo+gWekb84F/X9qttiAH//c+WM5G9S+OEQV9Xff6lecdaW4ZKKmRyxgsAH7plp9BJbmQrfjoWrqCQZOj9uypc2n0MLoUpg3WQxiDF+4I/n6Kj9PWrG0cft5jZqoiWHwDuZB+OE9gESZR0eu6oyEnvO6E36Bd5Fs95/U7wnHLvY6xQdwQQS0h26l51Rn7UedizGv/c1TnsbQNP1T1GXJydZ02UAXLAmt84xkCAwEAAaNQME4wHQYDVR0OBBYEFFfiUW6cHTScWqymoG2HlsXp4NR9MB8GA1UdIwQYMBaAFFfiUW6cHTScWqymoG2HlsXp4NR9MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJJPxpn991yLvzbZft7G/SiLKvU41B7PqB5chtUfDDn+rMvs+Fmx5SoyMv00HrkrT+dVNLYV6mDclRtB7MbAFnMoQLqNGx7DR4o/JhI9bT6hnioogu7gkDeOBjwBwEy9Wm4TwAa0/QXjpsJW9uTvfZLOwD3oMh3YcEmAKRC+eyGYWE67/gTB4JKwmFyJj0e/LKAzZhZGEGdFnpHwLm6M9fRUQNWY4ykbK0hN46B2nc/3r2MMMo0JcwLEXNBO9Qs/hTh5pr2bmTcGnkJHJrnwiTOZxHCYlY8Fv3xMSkq1At5eZJuPqq0RjYtbldLukqrJ0DO4gWxFxy/KBrTeTsjhJl4=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>'  # noqa


class XmlTest(unittest.TestCase):
    def _test(self, got, exp):
        # TODO: Maybe provide more meaningful output. YAGNI?
        msg = 'Did not get expected XML.\nExp: %s\nGot: %s' % (exp, got)
        self.assertEqual(exp, got, msg)

    def _test_template(self, template_source, parameters, exp):
        xml_render._get_in_response_to(parameters)
        xml_render._get_subject(parameters)
        xml_render._get_attribute_statement(parameters)
        got = string.Template(template_source).substitute(parameters)
        self._test(got, exp)


class TestSigning(XmlTest):
    def test1(self):
        signature_xml = get_signature_xml("this is a test", 'abcd' * 10)
        expected_xml = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>+ia+Gd5r/5P3C8IwhDTkpEC7rQI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>5lL2H6uxEVljKeiM4AEnhAZt3YIEJ6/fT75FUwFMD+UNOPaM9H1ks0Bgb0btFfTtRKByEBiUqJNOfDMG1iewdj1IG9ow6JH+Av7vHE1n2+xo956hptgcsVDwBlDDHSJhD99z+zT0bSDkk6i+bmpgqGO1z/y09TmhO24duNACqhEkeu1aXZIFgrnfZiYNWtHd4onLD7We4Q8UkB/3pGUHCCKtwDalq8S1xF6pvf0gh5f30+yj6T6rqGmbxb4iZ1p3yhlYVH8+7pRH39RapoPhuHsmGT5TLHjknzk/2HQoj/cqkAY1wKIlRYmX+jTADYTadbs9hhamv1QRTDNxJn+Mhw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDxzCCAq+gAwIBAgIJAPXQumUynZvpMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTAeFw0xNDA4MTkxMjUxNDlaFw0xNTA4MTkxMjUxNDlaMHoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQIDARHZW50MQ8wDQYDVQQKDAZBd2luZ3UxFDASBgNVBAsMC0RldmVsb3BtZW50MRMwEQYDVQQDDAphd2luZ3UuY29tMSAwHgYJKoZIhvcNAQkBFhF1c2FtYW1AYXdpbmd1LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPKQTRn0XoqhbNlBGFaSvjnHwd+zs0z3cpMZ6SnJy3bynaji06EQ31NFg5pd/XvUdElJv4HL2WE+CCY6R0mJADxk4vO9yuf0aw8sFqNoflUYgYfsO+LwIo+gWekb84F/X9qttiAH//c+WM5G9S+OEQV9Xff6lecdaW4ZKKmRyxgsAH7plp9BJbmQrfjoWrqCQZOj9uypc2n0MLoUpg3WQxiDF+4I/n6Kj9PWrG0cft5jZqoiWHwDuZB+OE9gESZR0eu6oyEnvO6E36Bd5Fs95/U7wnHLvY6xQdwQQS0h26l51Rn7UedizGv/c1TnsbQNP1T1GXJydZ02UAXLAmt84xkCAwEAAaNQME4wHQYDVR0OBBYEFFfiUW6cHTScWqymoG2HlsXp4NR9MB8GA1UdIwQYMBaAFFfiUW6cHTScWqymoG2HlsXp4NR9MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJJPxpn991yLvzbZft7G/SiLKvU41B7PqB5chtUfDDn+rMvs+Fmx5SoyMv00HrkrT+dVNLYV6mDclRtB7MbAFnMoQLqNGx7DR4o/JhI9bT6hnioogu7gkDeOBjwBwEy9Wm4TwAa0/QXjpsJW9uTvfZLOwD3oMh3YcEmAKRC+eyGYWE67/gTB4JKwmFyJj0e/LKAzZhZGEGdFnpHwLm6M9fRUQNWY4ykbK0hN46B2nc/3r2MMMo0JcwLEXNBO9Qs/hTh5pr2bmTcGnkJHJrnwiTOZxHCYlY8Fv3xMSkq1At5eZJuPqq0RjYtbldLukqrJ0DO4gWxFxy/KBrTeTsjhJl4=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>'  # noqa
        self._test(signature_xml, expected_xml)


class TestAssertionSalesForce(XmlTest):
    def test_assertion(self):
        # This test simply verifies that the template isn't bad.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(ASSERTION_SALESFORCE_PARAMS)
        self._test_template(ASSERTION_SALESFORCE, params,
                            ASSERTION_SALESFORCE_XML)

    def test_assertion_rendering(self):
        # Verifies that the xml rendering is OK.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(ASSERTION_SALESFORCE_PARAMS)
        got = xml_render.get_assertion_salesforce_xml(params, signed=False)
        self._test(got, ASSERTION_SALESFORCE_XML)

    def test_signed_assertion(self):
        # This test verifies that the assertion got signed properly.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(ASSERTION_SALESFORCE_PARAMS)
        got = xml_render.get_assertion_salesforce_xml(params, signed=True)
        self._test(got, SIGNED_ASSERTION_SALESFORCE_XML)


class TestResponse(XmlTest):
    def test_response(self):
        # This test simply verifies that the template isn't bad.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(RESPONSE_PARAMS)
        params['ASSERTION'] = ASSERTION_SALESFORCE_XML
        self._test_template(RESPONSE, params, RESPONSE_XML)

    def test_response_rendering(self):
        # Verifies that the rendering is OK.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(RESPONSE_PARAMS)
        params['ASSERTION'] = ASSERTION_SALESFORCE_XML
        got = xml_render.get_response_xml(params, signed=False)
        self._test(got, RESPONSE_XML)

    def test_response_with_signed_assertion(self):
        # This test also verifies that the template isn't bad.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(RESPONSE_PARAMS)
        params['ASSERTION'] = SIGNED_ASSERTION_SALESFORCE_XML
        got = xml_render.get_response_xml(params, signed=False)
        self._test(got, RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML)

    def test_signed_response_with_signed_assertion(self):
        # This test verifies that the response got signed properly.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(RESPONSE_PARAMS)
        params['ASSERTION'] = SIGNED_ASSERTION_SALESFORCE_XML
        got = xml_render.get_response_xml(params, signed=True)
        self._test(got, SIGNED_RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML)
