from setuptools import setup, find_packages
from saml2idp import __VERSION__

from setuptest import test


long_description = ''

with open('README.rst', 'r') as readme:
    long_description += readme.read()

with open('AUTHORS.rst', 'r') as authors:
    long_description += authors.read()

setup(
    author='Unomena',
    author_email='dev@unomena.com',
    classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: BSD License",
        "Development Status :: 4 - Beta",
        "Operating System :: OS Independent",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
    cmdclass={
        'test': test,
    },
    description='SAML 2.0 Django Application',
    name='django-saml2-idp',
    include_package_data=True,
    install_requires=[
        'beautifulsoup4==4.4.1',
        'pyOpenSSL==0.15.1',
    ],
    license='BSD',
    long_description=long_description,
    packages=find_packages(),
    tests_require=[
        'beautifulsoup4==4.4.1',
    ],
    url='http://github.com/unomena/django-saml2-idp',
    version=__VERSION__,
    zip_safe=False
)
