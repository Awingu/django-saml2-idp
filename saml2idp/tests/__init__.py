import os

from django.conf import settings
from django.test import override_settings

file_template = os.path.join(settings.PROJECT_ROOT, 'tests/keys/{}.pem')

certificate_file = file_template.format('certificate')
private_key_file = file_template.format('private-key')

config_with_file = settings.SAML2IDP_CONFIG.copy()
config_with_file.update({
    'certificate_file': certificate_file,
    'private_key_file': private_key_file,
})

override_settings_file = override_settings(SAML2IDP_CONFIG=config_with_file)

with open(certificate_file) as crt_file:
    certificate_str = crt_file.read()

with open(private_key_file) as pk_file:
    private_key_str = pk_file.read()

config_with_str = settings.SAML2IDP_CONFIG.copy()
config_with_str.update({
    'certificate_str': certificate_str,
    'private_key_str': private_key_str,
})

override_settings_str = override_settings(SAML2IDP_CONFIG=config_with_str)
