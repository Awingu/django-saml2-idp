from django.conf.urls import url, patterns

from saml2idp.views import descriptor, login_begin, login_init, login_process,\
    logout


urlpatterns = patterns(
    '',
    url(r'^login/$', login_begin, name="idp_login_begin"),
    url(r'^login/process/$', login_process, name='idp_login_process'),
    url(r'^logout/$', logout, name="idp_logout"),
    (r'^metadata/xml/$', descriptor),
    # For "simple" deeplinks:
    url(r'^init/(?P<resource>\w+)/(?P<target>\w+)/$', login_init,
        name="idp_login_init"),
)
