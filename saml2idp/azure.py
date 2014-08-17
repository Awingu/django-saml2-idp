# Other library imports:
from BeautifulSoup import BeautifulStoneSoup

# local app imports:
import base
import exceptions
import xml_render

# Default Azure ACS_URL.
AZURE_ACS_URL = 'https://login.microsoftonline.com/login.srf'

# Default Azure issuer in SAML request.
AZURE_REQUEST_ISSUER = 'urn:federation:MicrosoftOnline'

# Azure uses its own subject format for <NameID>
AZURE_SUBJECT_FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'


class Processor(base.Processor):
    """
    Microsoft Azure SAML 2.0 AuthnRequest to Response Handler Processor.
    """

    def _parse_request(self):
        """
        Parses various parameters from _request_xml into _request_params.
        We need to parse here as Microsoft Azure doesn't send
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
            raise exceptions.CannotHandleAssertion(
                'Request Issuer is invalid.')

    def _validate_user(self):
        """
        Validate if logged in User has sufficient attributes to generate
        response. Throw CannotHandleAssertion Exception if the validation
        does not succeed.
        """
        # TODO: Azure requires:
        # Subject: NameID
        # Attribute: IDPEmail
        pass

    def _determine_subject(self):
        """
        Determines _subject and _subject_type for Assertion Subject.
        Subject (NameID) should hold the user UPN ObjectGUID.
        We also add IDPEmail as an attribute.
        """
        # TODO: Find a clean way to get user ObjectGUID
        self._subject = 'aY1HH4WF7kuJ9qdyKH5kSQ=='
        self._idp_email = self._django_request.user.email

    def _determine_audience(self):
        """
        Determines the _audience.
        """
        self._audience = self._request_params.get('REQUEST_ISSUER', None)

    def _get_attributes(self):
        """
        Returns a dict of attributes to be added in response assertion.
        """
        # TODO: Move to base.Processor?!
        return {
            'IDPEmail': self._idp_email
        }

    def _format_assertion(self):
        """
        Format SAML Response Assertion.
        """
        # First, update our _assertion_params with required attributes
        attributes = self._get_attributes()
        self._assertion_params['ATTRIBUTES'] = attributes

        self._assertion_xml = xml_render.get_assertion_azure_xml(
            self._assertion_params, signed=True)
