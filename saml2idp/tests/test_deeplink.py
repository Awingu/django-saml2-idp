"""
Tests for the dj AttributeProcessor and IdP-initiated deep-linking.
"""

# local imports:
import os
import base

# Django imports:
from django.utils.unittest import skip
from django.core.urlresolvers import reverse


class TestDeepLink(base.SamlTestCase):

    @property
    def deeplink(self):
        return os.path.join(
            'http://127.0.0.1:8000',
            reverse('idp_login_init', args=[self.RESOURCE, self.TARGET]))

    SP_CONFIG = {
        'acs_url': 'http://127.0.0.1:9000/sp/acs/',
        'processor': 'saml2idp.dj.Processor',
        'links': {
            'deeplink': 'http://127.0.0.1:9000/sp/%s/',
        }
    }

    # DEEPLINK URL ARGS
    RESOURCE = 'deeplink'
    TARGET = 'test'

    EXPECTED_RELAY_STATE = 'http://127.0.0.1:9000/sp/test/'

    @skip('Skipping deeplinking for now!')
    def test_deeplink(self):
        # Arrange/Act:
        self._hit_saml_view(self.deeplink)
        # Assert:
        relaystate = self._html_soup.findAll('input',
                                             {'name': 'RelayState'})[0]
        self.assertEqual(self.EXPECTED_RELAY_STATE, relaystate['value'])


class TestDeepLinkWithAttributes(TestDeepLink):

    SP_CONFIG = {
        'acs_url': 'http://127.0.0.1:9000/sp/acs/',
        'processor': 'saml2idp.dj.AttributeProcessor',
        'links': {
            'attr': 'http://127.0.0.1:9000/sp/%s/',
        },
    }

    # DEEPLINK URL ARGS
    RESOURCE = 'attr'
    TARGET = 'test'

    EXPECTED_RELAY_STATE = 'http://127.0.0.1:9000/sp/test/'

    @skip('saml2idp.dj does not have AttributeProcessor.')
    def test_deeplink(self):
        super(TestDeepLinkWithAttributes, self).test_deeplink()
        attributes = self._saml_soup.findAll('saml:attribute')

        # Assert.
        self.assertEqual(len(attributes), 1)
        self.assertEqual(attributes[0]['name'], 'foo')
        value = attributes[0].findAll('saml:attributevalue')[0]
        self.assertEqual(value.text, 'bar')
