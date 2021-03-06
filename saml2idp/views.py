# Django/other library imports:
from django.utils.log import logging
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response, redirect
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseForbidden

# saml2idp app imports:
from . import saml2idp_metadata
from . import exceptions
from . import metadata
from . import registry
from . import xml_signing


logger = logging.getLogger('saml2idp')


def _generate_response(request, processor):
    """
    Generate a SAML response using processor and return it in the proper Django
    response.
    """
    try:
        tv = processor.generate_response()
    except exceptions.UserNotAuthorized:
        return render_to_response('saml2idp/invalid_user.html',
                                  context_instance=RequestContext(request))

    return render_to_response('saml2idp/login.html', tv,
                              context_instance=RequestContext(request))


def xml_response(request, template, tv, context_instance=None):
    return render_to_response(template, tv, context_instance=context_instance,
                              mimetype="application/xml")


@csrf_exempt
def login_begin(request, *args, **kwargs):
    """
    Receives a SAML 2.0 AuthnRequest from a Service Provider and
    stores it in the session prior to enforcing login.
    """
    if request.method == 'POST':
        source = request.POST
    else:
        source = request.GET
    # Store these values now, because Django's login cycle won't preserve them.
    saml_req = source.get('SAMLRequest')
    relay_state = source.get('RelayState')

    if not saml_req or not relay_state:
        return HttpResponseForbidden()

    request.session['SAMLRequest'] = saml_req
    request.session['RelayState'] = relay_state

    return redirect('idp_login_process')


@login_required
def login_init(request, resource, **kwargs):
    """
    Initiates an IdP-initiated link to a simple SP resource/target URL.
    """
    sp_config = metadata.get_config_for_resource(resource)
    proc_path = sp_config['processor']
    proc = registry.get_processor(proc_path)
    try:
        linkdict = dict(metadata.get_links(sp_config))
        pattern = linkdict[resource]
    except KeyError:
        raise ImproperlyConfigured(
            'Cannot find link resource in SAML2IDP_REMOTE setting: "%s"'
            % resource)

    is_simple_link = ('/' not in resource)
    if is_simple_link:
        simple_target = kwargs['target']
        url = pattern % simple_target
    else:
        url = pattern % kwargs
    proc.init_deep_link(request, sp_config, url)
    return _generate_response(request, proc)


@login_required
def login_process(request):
    """
    Processor-based login continuation.
    Presents a SAML 2.0 Assertion for POSTing back to the Service Provider.
    """
    # reg = registry.ProcessorRegistry()
    logger.debug("Request: %s" % request)

    # Set metadata config in request session!
    try:
        config, remotes = saml2idp_metadata.get_metadata_config(request)
        request.session['SAML2IDP'] = {
            'SAML2IDP_CONFIG': config,
            'SAML2IDP_REMOTES': remotes,
        }
    except:
        logger.exception('Failed to load SAML2IDP configuration!')
        return HttpResponseForbidden()

    try:
        proc = registry.find_processor(request)
    except exceptions.CannotHandleAssertion:
        logger.exception('No processor to handle request!')
        return HttpResponseForbidden()

    return _generate_response(request, proc)


@csrf_exempt
def logout(request):
    """
    Allows a non-SAML 2.0 URL to log out the user and
    returns a standard logged-out page. (SalesForce and others use this method,
    though it's technically not SAML 2.0).
    """
    try:
        saml2idp_config = request.session['SAML2IDP']['SAML2IDP_CONFIG']

        # First, check if we are required to bypass logout.
        logout_disabled = saml2idp_config.get('logout_disabled', False)

        if logout_disabled:
            return bypass_logout(saml2idp_config)
    except:
        pass

    auth.logout(request)
    tv = {}
    return render_to_response('saml2idp/logged_out.html', tv,
                              context_instance=RequestContext(request))


def bypass_logout(saml2idp_config):
    """
    Checks if logout is disabled in IDP config, and redirects to optional url
    or directly to '/'
    """
    redirect_url = saml2idp_config.get('logout_bypass_url', '/')

    return redirect(redirect_url)


@login_required
@csrf_exempt
def slo_logout(request):
    """
    Receives a SAML 2.0 LogoutRequest from a Service Provider,
    logs out the user and returns a standard logged-out page.
    """
    request.session['SAMLRequest'] = request.POST['SAMLRequest']
    # TODO: Parse SAML LogoutRequest from POST data, similar to login_process()
    # TODO: Add a URL dispatch for this view.
    # TODO: Modify the base processor to handle logouts?
    # TODO: Combine this with login_process(), since they are so very similar?
    # TODO: Format a LogoutResponse and return it to the browser.
    # XXX: For now, simply log out without validating the request.

    # check if we are required to bypass logout
    saml2idp_config = request.session['SAML2IDP']['SAML2IDP_CONFIG']

    logout_disabled = saml2idp_config.get('logout_disabled', False)

    if logout_disabled:
        return bypass_logout()

    auth.logout(request)
    tv = {}
    return render_to_response('saml2idp/logged_out.html', tv,
                              context_instance=RequestContext(request))


def descriptor(request):
    """Replies with the XML Metadata IDSSODescriptor."""

    config = request.session['SAML2IDP']['SAML2IDP_CONFIG']

    tv = {
        'cert_public_key': xml_signing.load_certificate_data(config),
        'entity_id': config['issuer'],
        'slo_url': request.build_absolute_uri(reverse('logout')),
        'sso_url': request.build_absolute_uri(reverse('login_begin')),
    }

    return xml_response(
        request, 'saml2idp/idpssodescriptor.xml', tv,
        context_instance=RequestContext(request))
