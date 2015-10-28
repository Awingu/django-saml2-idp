"""
Tests for basic view functionality only.

NOTE: These classes do not test anything SAML-related.
Testing actual SAML functionality requires implementation-specific details,
which should be put in another test module.
"""
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse

from django.conf import settings

from django.test import TestCase


SAML_REQUEST = 'this is not a real SAML Request'
RELAY_STATE = 'abcdefghi0123456789'
REQUEST_DATA = {
    'SAMLRequest': SAML_REQUEST,
    'RelayState': RELAY_STATE,
}


class ViewTestCase(TestCase):

    @property
    def login_url(self):
        return reverse('idp_login_begin')

    @property
    def logout_url(self):
        return reverse('idp_logout')

    @property
    def login_process_url(self):
        return reverse('idp_login_process')

    def login_user(self):
        User.objects.create_user('fred',
                                 email='fred@example.com',
                                 password='secret')

        self.client.login(username='fred', password='secret')

        self.assertTrue('_auth_user_id' in self.client.session,
                        'Did not login test user; test is broken.')

        session = self.client.session
        session['SAML2IDP'] = {
            'SAML2IDP_CONFIG': settings.SAML2IDP_CONFIG,
            'SAML2IDP_REMOTES': {},
        }
        session.save()


class TestLoginView(ViewTestCase):

    def test_empty_get(self):
        """
        GET request without SAMLResponse data should have failed.
        """
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 403)

    def test_empty_post(self):
        """
        POST request without SAMLResponse data should have failed.
        """
        response = self.client.post(self.login_url)
        self.assertEqual(response.status_code, 403)

    def _test_pre_redirect(self):
        self.assertFalse('SAMLRequest' in self.client.session)
        self.assertFalse('RelayState' in self.client.session)

    def _test_redirect(self, response):
        self.assertEquals(response.status_code,
                          HttpResponseRedirect.status_code)
        self.assertTrue(response['location'].endswith(self.login_process_url))
        self.assertEqual(self.client.session['SAMLRequest'], SAML_REQUEST)
        self.assertEqual(self.client.session['RelayState'], RELAY_STATE)

    def test_get(self):
        """
        GET did not redirect to process URL.
        """
        self._test_pre_redirect()
        response = self.client.get(self.login_url, data=REQUEST_DATA)
        self._test_redirect(response)

    def test_post(self):
        """
        POST did not redirect to process URL.
        """
        self._test_pre_redirect()
        response = self.client.post(self.login_url, data=REQUEST_DATA)
        self._test_redirect(response)


class TestLoginProcessView(ViewTestCase):

    def test_process_request_not_authorized(self):
        """
        Bogus request should have triggered exception.
        """

        # Arrange: login new user and setup session variables.
        User.objects.create_user('fred',
                                 email='fred@example.com',
                                 password='secret')
        self.client.login(username='fred', password='secret')
        session = self.client.session
        session['RelayState'] = RELAY_STATE
        session['SAMLRequest'] = SAML_REQUEST
        session.save()

        # Act and assert:
        response = self.client.get(self.login_process_url)
        self.assertEqual(response.status_code, 403)


class TestLogoutView(ViewTestCase):
    def test_logout(self):
        """
        Response did not say logged out.
        """
        self.login_user()
        response = self.client.get(self.logout_url)
        self.assertContains(response, 'logged out', status_code=200)

    def test_logout_user(self):
        """
        User account not logged out.
        """
        response = self.client.get(self.logout_url)

        self.assertTrue('_auth_user_id' not in self.client.session,
                        'Did not logout test user.')

        self.assertTrue('logged out' in response.content)

    def test_logout_disabled(self):
        """
        Test disabled logout.
        """
        settings.SAML2IDP_CONFIG.update({
            'logout_disabled': True,
            'logout_bypass_url': '/'
        })
        self.login_user()

        response = self.client.get(self.logout_url)

        self.assertFalse('logged out' in response.content)

        self.assertEqual(response.status_code, 302)
