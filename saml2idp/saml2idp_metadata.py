"""
Django Settings that more closely resemble SAML Metadata.

Detailed discussion is in doc/SETTINGS_AND_METADATA.txt.
"""
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.importlib import import_module


def get_metadata_config(request):
    """
    Get Metadata based on configuration in settings.

    Options are:
        - SAML2IDP_REMOTES & SAML2IDP_CONFIG present in settings
        - SAML2IDP_CONFIG_FUNCTION will be used to get REMOTES and CONFIG
          per request. Dynamic way of loading configuration.

    :return: Tuple holding SAML2IDP_CONFIG, SAML2IDP_REMOTES
    """
    if hasattr(settings, 'SAML2IDP_CONFIG_FUNCTION'):
        # We have a dynamic configuration.
        config_func = import_function_from_str(
            settings.SAML2IDP_CONFIG_FUNCTION)

        if not config_func:
            raise ImproperlyConfigured(
                'Cannot import SAML2IDP_CONFIG_FUNCTION')

        # Return SAML2IDP_CONFIG & SAML2IDP_REMOTES
        return config_func(request)
    elif (hasattr(settings, 'SAML2IDP_CONFIG') and
            hasattr(settings, 'SAML2IDP_REMOTES')):
        # We have static configuration!
        return settings.SAML2IDP_CONFIG, settings.SAML2IDP_REMOTES

    raise ImproperlyConfigured('Cannot load SAML2IDP configuration!')


def import_function_from_str(func):
    """
    Import function from string.

    :param func: Can be a string or a function
    """
    if isinstance(func, basestring):
        # function supplied as a string
        mod_str, _, func_str = func.rpartition('.')
        try:
            mod = import_module(mod_str)
            return getattr(mod, func_str)
        except:
            return None

    return func
