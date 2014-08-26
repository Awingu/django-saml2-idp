# Other library imports:
from BeautifulSoup import BeautifulStoneSoup

# local app imports:
import base
import xml_render
from exceptions import CannotHandleAssertion

from django.utils.importlib import import_module
from django.core.exceptions import ImproperlyConfigured

# Default Azure ACS_URL.
AZURE_ACS_URL = 'https://login.microsoftonline.com/login.srf'

# Default Azure issuer in SAML request.
AZURE_REQUEST_ISSUER = 'urn:federation:MicrosoftOnline'

# Azure uses its own subject format for <NameID>
AZURE_SUBJECT_FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'


class Processor(base.Processor):
    """
    Microsoft Azure SAML 2.0 AuthnRequest to Response Handler Processor.

    IMPORTANT
    Azure SP configuration should include 'subject_function' which is a
    function used by Azure processor to retrieve Subject NameID (ImmutableID).

    You can use: from saml2idp.codex import convert_guid_to_immutable_id

    Example of subject_function:

    def get_subject_from_django_user(django_request):
        from saml2idp.codex import convert_guid_to_immutable_id

        # get ObjectGUID from Django user
        object_guid = get_user_object_guid(django_request.user)

        # return the ImmutableID from object_guid
        return convert_guid_to_immutable_id(object_guid)

    Example Azure SP configuration in SAML2IDP_REMOTES:

    azure_config = {
        'acs_url': 'https://login.microsoftonline.com/login.srf',
        'processor': 'saml2idp.azure.Processor',
        'subject_function': get_subject_from_django_user
        # or as a string
        # 'subject_function': 'pkg.mod.get_subject_from_django_user'
    }

    SAML2IDP_REMOTES = {
        'azure': azure_config
    }
    """

    def _parse_request(self):
        """
        Parses various parameters from _request_xml into _request_params.
        We need to override parse here as Microsoft Azure doesn't send
        AssertionConsumerServiceURL (ACS_URL)
        """
        # Minimal test to verify that it's not binarily encoded still:
        if not self._request_xml.strip().startswith('<'):
            raise Exception('RequestXML is not valid XML; '
                            'it may need to be decoded or decompressed.')

        soup = BeautifulStoneSoup(self._request_xml)
        request = soup.findAll()[0]

        if request.get('assertionconsumerserviceurl', None):
            raise Exception(
                'Invalid Azure request. AssertionConsumerServiceURL exists!')

        params = {}
        params['ACS_URL'] = AZURE_ACS_URL
        params['REQUEST_ID'] = request['id']

        params['REQUEST_ISSUER'] = self._get_request_issuer(request)

        params['DESTINATION'] = request.get('destination', '')
        params['PROVIDER_NAME'] = request.get('providername', '')

        self._request_params = params

        # Set subject format - overrides the value set in _reset()
        self._subject_format = AZURE_SUBJECT_FORMAT

    def _get_request_issuer(self, saml_request):
        """
        Get Request issuer.

        :params saml_request: SAML XML BeautifulSoup request object.
        """
        issuer = [i for i in saml_request.contents if 'issuer' in i.name]

        if issuer:
            return issuer[0].getText()

        return None

    def _validate_request(self):
        """
        Validates the _saml_request.
        """
        super(Processor, self)._validate_request()

        if self._request_params.get('REQUEST_ISSUER') != AZURE_REQUEST_ISSUER:
            raise CannotHandleAssertion('Request Issuer is invalid.')

    def _validate_user(self):
        """
        Validate if logged in User has sufficient attributes to generate
        response. Throw CannotHandleAssertion Exception if the validation
        does not succeed.

        Microsoft Azure requires NameID and IDPEmail. NameID must be retrieved
        by sp_config['subject_function'].
        """
        if not self._sp_config.get('subject_function', None):
            # We won't be able to get NameID of the user!
            raise CannotHandleAssertion(
                'Missing "subject_function" in Azure config found in '
                'SAML2IDP_REMOTES setting.')

        if not self._get_subject_function():
            # Invalid subject function
            raise ImproperlyConfigured(
                'Error importing subject_function: %s'
                % self._sp_config['subject_function'])

        if not self._django_request.user.email:
            raise CannotHandleAssertion('Invalid user email.')

    def _determine_subject(self):
        """
        Determines _subject for Assertion Subject.

        We need to get Subject (NameID) and add IDPEmail as an attribute.
        This method calls sp_config['subject_function'] to get NameID, and it
        will use django user email as the IDPEmail.

        NameID: is the Office 365 ImmutableID. ImmutableID is derived from
        user AD ObjectGUID. Check codex.convert_guid_to_immutable_id for
        implementation.
        """
        subject_function = self._get_subject_function()
        self._subject = subject_function(self._django_request)
        self._idp_email = self._django_request.user.email

    def _get_subject_function(self):
        """
        Returns the subject_function from SP config.

        sp_config['subject_function'] can be a string or a function.
        """
        subject_function = self._sp_config['subject_function']

        if isinstance(subject_function, basestring):
            # function supplied as a string
            parts = subject_function.split('.')

            mod_str = '.'.join(parts[:-1])  # module string
            func_str = parts[-1]  # function string
            try:
                mod = import_module(mod_str)
                return getattr(mod, func_str)
            except:
                return None

        return subject_function

    def _determine_audience(self):
        """
        Determines the _audience.
        """
        self._audience = AZURE_REQUEST_ISSUER

    def _get_attributes(self):
        """
        Returns a dict of attributes to be added in response assertion.

        Mainly adding the IDPEmail attribute.
        """
        return {
            'IDPEmail': self._idp_email
        }

    def _format_assertion(self):
        """
        Format SAML Response Assertion.
        """
        self._assertion_xml = xml_render.get_assertion_azure_xml(
            self._assertion_params, signed=True)
