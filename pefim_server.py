import base64
from uuid import uuid4
from saml2.config import config_factory
from saml2.httputil import ServiceError, NotFound, Response
import sys
from pefimproxy.back import SamlSP
from pefimproxy.front import SamlIDP
import pefim_server_conf
import logging
import re
from logging.handlers import BufferingHandler

#External imports
import importlib
import argparse
from cherrypy import wsgiserver
from cherrypy.wsgiserver import ssl_pyopenssl
from beaker.middleware import SessionMiddleware
from mako.lookup import TemplateLookup
from saml2.s_utils import exception_trace
from os import path
from pefimproxy.server import WsgiApplication
from pefimproxy.util.config import get_configurations
from pefimproxy.util.http import HttpHelper, Session
from saml2.authn_context import AuthnBroker, authn_context_class_ref, UNSPECIFIED


def application(environ, start_response):
    return wsgi_app.run_server(environ, start_response)

if __name__ == '__main__':
    args = WsgiApplication.arg_parser()

    global wsgi_app
    wsgi_app = WsgiApplication(pefim_server_conf, args, base_dir=path.dirname(path.realpath(__file__)) + "/")

    global SRV
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', pefim_server_conf.PORT), SessionMiddleware(
        application,
        pefim_server_conf.SESSION_OPTS))
    SRV.stats['Enabled'] = True

    if pefim_server_conf.HTTPS:
        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(pefim_server_conf.SERVER_CERT, pefim_server_conf.SERVER_KEY,
                                                         pefim_server_conf.CERT_CHAIN)
    wsgi_app.logger.info("Server starting")
    print "Server listening on port: %s" % pefim_server_conf.PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
