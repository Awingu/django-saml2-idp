from setuptools import setup, find_packages

try:
    # For development. It helps running tests with --label arg.
    # Example: python setup.py test --label saml2idp.TestAzureProcessor
    from setuptest import test
    CMDCLASS = {'test': test}
except ImportError:
    CMDCLASS = {}

from saml2idp import __VERSION__


setup(
    name='django-saml2-idp',
    version=__VERSION__,
    description='SAML 2.0 Django Application',
    long_description=open('README.rst', 'r').read() +
    open('AUTHORS.rst', 'r').read(),
    author='Unomena',
    author_email='dev@unomena.com',
    license='BSD',
    url='http://github.com/unomena/django-saml2-idp',
    packages=find_packages(),
    install_requires=[
        'BeautifulSoup==3.2.1',
        'M2Crypto==0.22.3',
    ],
    tests_require=[
        'BeautifulSoup==3.2.1',
    ],
    test_suite="setuptest.setuptest.SetupTestSuite",
    cmdclass=CMDCLASS,
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: BSD License",
        "Development Status :: 4 - Beta",
        "Operating System :: OS Independent",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
    zip_safe=False,
)
