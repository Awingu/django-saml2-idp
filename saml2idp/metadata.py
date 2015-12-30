"""
Query metadata from settings.
"""
# Django imports
from django.core.exceptions import ImproperlyConfigured


def get_config_for_acs(request, acs_url):
    """
    Return SP configuration instance that handles acs_url.
    """
    saml2idp_remotes = request.session['SAML2IDP']['SAML2IDP_REMOTES']
    for friendlyname, config in list(saml2idp_remotes.items()):
        if config['acs_url'] == acs_url:
            return config

    msg = 'SAML2IDP_REMOTES is not configured to handle the '
    'AssertionConsumerService at "%s"'

    raise ImproperlyConfigured(msg % acs_url)


def get_config_for_resource(request, resource_name):
    """
    Return the SP configuration that handles a deep-link resource_name.
    """
    saml2idp_remotes = request.session['SAML2IDP']['SAML2IDP_REMOTES']
    for friendlyname, config in list(saml2idp_remotes.items()):
        links = get_links(config)
        for name, pattern in links:
            if name == resource_name:
                return config

    msg = 'SAML2IDP_REMOTES is not configured to handle a link resource "%s"'

    raise ImproperlyConfigured(msg % resource_name)


def get_deeplink_resources():
    """
    Returns a list of resources that can be used for deep-linking.

    Note: Removed for the sake of dynamic configuration.
    """
    pass


def get_links(sp_config):
    """
    Returns a list of (resource, pattern) tuples for the 'links' for an sp.
    """
    links = sp_config.get('links', [])
    if type(links) is dict:
        links = list(links.items())
    return links
