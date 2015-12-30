"""
Tests for the Microsoft Azure processor.
"""
import uuid
import base64

from django.core.exceptions import ImproperlyConfigured
from django.utils.unittest import skip

# local imports:
from . import base

from saml2idp import saml2idp_metadata
from saml2idp.azure import AZURE_ACS_URL
from saml2idp.exceptions import CannotHandleAssertion
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

USER_SUBJECT_FUNCTION = 'saml2idp.tests.test_azure.get_user_subject'


def get_user_subject(django_request):
    guid = '1f478d69-8585-4bee-89f6-a772287e6449'
    return convert_guid_to_immutable_id(guid)


def get_user_idp_email(django_request, attribute):
    return 'freddy@example.com'


class TestAzureProcessor(base.TestBaseProcessor):
    SP_CONFIG = {
        'acs_url': AZURE_ACS_URL,
        'processor': 'saml2idp.azure.Processor',
        'subject_function': USER_SUBJECT_FUNCTION
    }

    REQUEST_DATA = REQUEST_DATA

    def tearDown(self):
        self.SP_CONFIG.pop('attribute_function', None)
        self.SP_CONFIG['subject_function'] = USER_SUBJECT_FUNCTION
        super(TestAzureProcessor, self).tearDown()

    def test_user_logged_in(self):
        """
        Check Email and ImmutableID
        """
        super(TestAzureProcessor, self).test_user_logged_in()
        self.assertTrue(get_user_subject(None) in self._saml)

    def test_subject_function_str(self):
        """
        Test subject_function as string.
        """
        self.SP_CONFIG['subject_function'] = USER_SUBJECT_FUNCTION

        super(TestAzureProcessor, self).test_user_logged_in()
        self.assertTrue(get_user_subject(None) in self._saml)

    def test_invalid_sp_config(self):
        """
        Missing subject_function.
        """
        self.SP_CONFIG.pop('subject_function')

        with self.assertRaises(CannotHandleAssertion):
                super(TestAzureProcessor, self).test_user_logged_in()

    def test_subject_function_str_invalid(self):
        """
        Missing subject_function.
        """
        self.SP_CONFIG['subject_function'] = (
            'saml2idp.tests.test_azure.get_user_subject_doesnot_exist')

        with self.assertRaises(ImproperlyConfigured):
                super(TestAzureProcessor, self).test_user_logged_in()

    @skip('Functions cannot be stored in session?')
    def test_attribute_function(self):
        """
        Test attribute_function.
        """
        self.SP_CONFIG['attribute_function'] = get_user_idp_email
        saml2idp_metadata.SAML2IDP_REMOTES['foobar'] = self.SP_CONFIG

        self.EMAIL = get_user_idp_email(None, None)

        super(TestAzureProcessor, self).test_user_logged_in()

    def test_attribute_function_str(self):
        """
        Test attribute_function as string.
        """
        self.SP_CONFIG['attribute_function'] = (
            'saml2idp.tests.test_azure.get_user_idp_email')

        self.EMAIL = get_user_idp_email(None, None)

        super(TestAzureProcessor, self).test_user_logged_in()

    def test_attribute_function_str_invalid(self):
        """
        Test invalid attribute_function as string.
        """
        self.SP_CONFIG['attribute_function'] =\
            'saml2idp.tests.azure.get_user_idp_email_does_not_exist'

        super(TestAzureProcessor, self).test_user_logged_in()
        self.assertFalse(get_user_idp_email(None, None) in self._saml)

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
