"""
Tests for the Microsoft Azure processor.
"""
import uuid
import base64

# local imports:
import base

from saml2idp.azure import AZURE_ACS_URL
from saml2idp.codex import convert_guid_to_immutable_id


SAML_REQUEST = base64.b64encode(
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    'ID="doljiidhacjcjifebimhedigpeejhpifpdmlbjai" Version="2.0" '
    'AssertionConsumerServiceIndex="0" '
    'IssueInstant="2011-10-05T17:49:29Z">'
    '<saml:Issuer>urn:federation:MicrosoftOnline</saml:Issuer>'
    '<samlp:NameIDPolicy '
    'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>'
    '</samlp:AuthnRequest>'
)

RELAY_STATE = (
    'A6Dl2zRFPgqdgYztvWxW6M8gXuBK'
)

REQUEST_DATA = {
    'SAMLRequest': SAML_REQUEST,
    'RelayState': RELAY_STATE,
}


def get_user_subject(django_request):
    guid = '1f478d69-8585-4bee-89f6-a772287e6449'
    return convert_guid_to_immutable_id(guid)


class TestAzureProcessor(base.TestBaseProcessor):
    SP_CONFIG = {
        'acs_url': AZURE_ACS_URL,
        'processor': 'saml2idp.azure.Processor',
        'subject_function': get_user_subject
    }

    REQUEST_DATA = REQUEST_DATA

    def test_user_logged_in(self):
        """
        Check Email and ImmutableID
        """
        super(TestAzureProcessor, self).test_user_logged_in()
        self.assertTrue(get_user_subject(None) in self._saml)

    def test_convert_guid_str(self):
        """
        Test convert_guid_to_immutable_id
        """
        guid = '1f478d69-8585-4bee-89f6-a772287e6449'
        immutable_id = 'aY1HH4WF7kuJ9qdyKH5kSQ=='

        self.assertEqual(immutable_id, convert_guid_to_immutable_id(guid))

    def test_convert_guid_uuid(self):
        """
        Test convert_guid_to_immutable_id
        """
        guid = uuid.UUID('1f478d69-8585-4bee-89f6-a772287e6449')
        immutable_id = 'aY1HH4WF7kuJ9qdyKH5kSQ=='

        self.assertEqual(immutable_id, convert_guid_to_immutable_id(guid))

    def test_convert_guid_invalid(self):
        """
        Test convert_guid_to_immutable_id
        """
        guid = uuid.UUID('1f478d69-8585-4bee-89f6-a77777777777')
        immutable_id = 'aY1HH4WF7kuJ9qdyKH5kSQ=='

        self.assertNotEqual(immutable_id, convert_guid_to_immutable_id(guid))
