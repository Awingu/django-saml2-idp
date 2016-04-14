import hashlib
import logging
import string

import OpenSSL

from .codex import nice64
from .xml_templates import SIGNED_INFO, SIGNATURE


def load_certificate_data(config):
    certificate_str = config.get('certificate_str')

    if certificate_str is None:
        certificate_file = config.get('certificate_file')

        logging.debug('Using certificate file: '.format(certificate_file))

        with open(certificate_file) as file:
            certificate_str = file.read()

    return ''.join(certificate_str.split('\n')[1:-2])


def load_private_key(config):
    private_key_str = config.get('private_key_str')

    if private_key_str is None:
        private_key_file = config['private_key_file']

        logging.debug('Using private key file: ' + private_key_file)

        with open(private_key_file) as file:
            private_key_str = file.read()
    else:
        logging.debug('Using private key string')

    return OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, private_key_str)


def get_signature_xml(config, subject, reference_uri):
    """Returns XML Signature for subject."""

    logging.debug('Subject: {}'.format(subject))

    # Hash the subject.
    subject_hash = hashlib.sha1()
    subject_hash.update(subject.encode())
    subject_digest = nice64(subject_hash.digest())

    logging.debug('Subject digest: {}'.format(subject_digest))

    # Create signed_info.
    signed_info = string.Template(SIGNED_INFO).substitute({
        'REFERENCE_URI': reference_uri,
        'SUBJECT_DIGEST': subject_digest,
    })

    logging.debug('SignedInfo XML: {}'.format(signed_info))

    # RSA-sign the signed_info.
    private_key = load_private_key(config)
    signed_private_key = OpenSSL.crypto.sign(private_key, signed_info, 'sha1')
    rsa_signature = nice64(signed_private_key)

    logging.debug('RSA Signature: {}'.format(rsa_signature))

    # Load the certificate.
    certificate = load_certificate_data(config)

    # Put the signed_info and rsa_signature into the XML signature.
    signed_info_short = signed_info.replace(
        ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"', '')
    signature_xml = string.Template(SIGNATURE).substitute({
        'CERTIFICATE': certificate,
        'RSA_SIGNATURE': rsa_signature,
        'SIGNED_INFO': signed_info_short,
    })

    logging.debug('Signature XML: {}'.format(signature_xml))

    return signature_xml
