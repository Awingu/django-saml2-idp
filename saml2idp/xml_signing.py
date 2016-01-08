"""
Signing code goes here.
"""
# python:
import hashlib
import logging
import string
import os
# other libraries:
import OpenSSL
# this app:
from . import saml2idp_metadata
from .codex import nice64
from .xml_templates import SIGNED_INFO, SIGNATURE


def load_private_key(private_key):
    """Load private key from file or key string"""
    if os.path.exists(private_key):
        with open(private_key) as f:
            private_key = f.read()

    return OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, private_key)


def load_cert_data(certificate_file):
    """
    Returns the certificate data out of the certificate_file.
    """
    if os.path.exists(certificate_file):
        with open(certificate_file) as f:
            certificate_file = f.read()
    cert_data = ''.join(certificate_file.split('\n')[1:-2])
    return cert_data


def get_signature_xml(saml2idp_config, subject, reference_uri):
    """
    Returns XML Signature for subject.
    """

    private_key_file = saml2idp_config['private_key_file']
    certificate_file = saml2idp_config['certificate_file']

    logging.debug('get_signature_xml - Begin.')
    logging.debug('Using private key file: ' + private_key_file)
    logging.debug('Using certificate file: ' + certificate_file)
    logging.debug('Subject: ' + subject)

    # Hash the subject.
    subject_hash = hashlib.sha1()
    if isinstance(subject, str):
        subject_hash.update(subject.encode('utf-8'))
    else:
        subject_hash.update(subject)
    subject_digest = nice64(subject_hash.digest())

    logging.debug('Subject digest: ' + subject_digest)

    # Create signed_info.
    signed_info = string.Template(SIGNED_INFO).substitute({
        'REFERENCE_URI': reference_uri,
        'SUBJECT_DIGEST': subject_digest,
    })

    logging.debug('SignedInfo XML: ' + signed_info)

    # RSA-sign the signed_info.
    private_key = load_private_key(private_key_file)
    rsa_signature = nice64(
        OpenSSL.crypto.sign(private_key, signed_info.encode('utf-8'), 'sha1'))
    logging.debug('RSA Signature: ' + rsa_signature)

    # Load the certificate.
    cert_data = load_cert_data(certificate_file.encode('utf-8'))

    # Put the signed_info and rsa_signature into the XML signature.
    signed_info_short = signed_info.replace(
        ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"', '')
    signature_xml = string.Template(SIGNATURE).substitute({
        'RSA_SIGNATURE': rsa_signature,
        'SIGNED_INFO': signed_info_short,
        'CERTIFICATE': cert_data,
    })

    logging.debug('Signature XML: ' + signature_xml)

    return signature_xml
