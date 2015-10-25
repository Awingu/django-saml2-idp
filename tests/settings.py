import os
PROJECT_ROOT = os.getcwd()


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'saml2idp.db',
    }
}

ROOT_URLCONF = 'saml2idp.urls'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'saml2idp',
)

TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

TEMPLATE_DIRS = (
    os.path.join(PROJECT_ROOT, 'tests/templates'),
)

MIDDLEWARE_CLASSES = [
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',

]

# # SAML2IDP metadata settings
SAML2IDP_CONFIG = {
    'autosubmit': True,
    'issuer': 'http://127.0.0.1:8000/',
    'signing': True,
    'certificate_file': os.path.join(PROJECT_ROOT,
                                     'tests/keys/certificate.pem'),
    'private_key_file': os.path.join(PROJECT_ROOT,
                                     'tests/keys/private-key.pem'),
}


# Example Google Apps SP config:
# google_apps_config = {
#     'acs_url': 'https://www.google.com/a/awingu.com/acs',
#     'processor': 'saml2idp.google_apps.Processor',
# }


# Example Microsoft Azure SP config:
# def get_user_subject(django_request):
#     """Dummy function"""
#     return 'aY1HH4WF7kuJ9qdyKH5kSQ=='

# azure_config = {
#     'acs_url': 'https://login.microsoftonline.com/login.srf',
#     'processor': 'saml2idp.azure.Processor',
#     'subject_function': get_user_subject
# }

SAML2IDP_REMOTES = {
    # Group of SP CONFIGs.
    # friendlyname: SP config
    # 'google_apps': google_apps_config,
    # 'azure': azure_config
}
