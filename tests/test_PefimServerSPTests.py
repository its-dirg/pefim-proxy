from test.TestSp import TestSp

__author__ = 'haho0032'

from os import path
import os

from saml2 import BINDING_HTTP_REDIRECT
import cherrypy
from cherrypy.test import helper
from beaker.middleware import SessionMiddleware
from argparse import Namespace

from test.TestHelper import create_cookie_header, get_url_dict, get_post_action_body
from test.TestIdP import TestIdP
import pefim_server_conf_local
from pefimproxy.server import WsgiApplication


class PefimServerSPTests(helper.CPWebCase):
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    ARGS = Namespace(debug=False,
                     entityid="http://test.idp.se:1111/TestIdP.xml",
                     config="pefim_proxy_conf_local")

    WSGI_APP = WsgiApplication(pefim_server_conf_local, ARGS,
                               base_dir=path.dirname(path.realpath(__file__)) + "/../")

    @staticmethod
    def application(environ, start_response):
        return PefimServerSPTests.WSGI_APP.run_server(environ, start_response)

    def setup_server():
        cherrypy.tree.graft(SessionMiddleware(PefimServerSPTests.application, pefim_server_conf_local.SESSION_OPTS),
                            '/')
        pass

    setup_server = staticmethod(setup_server)


    def test_complete_flow(self):
        test_sp = TestSp(self.BASEDIR)
        url = test_sp.create_authn_request()
        self.getPage(url)
        self.assertStatus('303 See Other')
        req = get_url_dict(self.headers)
        self.assertTrue("SAMLRequest" in req)
        self.assertTrue("RelayState" in req)
        test_idp = TestIdP(self.BASEDIR)
        action, body = test_idp.handle_authn_request(req["SAMLRequest"][0], req["RelayState"][0], BINDING_HTTP_REDIRECT,
                                                     "testuser1")
        cookies = create_cookie_header(self.cookies)
        self.getPage(action, headers=cookies, method='POST', body=body)
        action, body = get_post_action_body(self.body)
        self.assertStatus('200 OK')
        self.assertTrue('http://test.sp.se:8900/acs/post' == action, "Must be designated for the right SP!")
        resp = test_sp.eval_authn_response(body["SAMLResponse"])
        self.assertTrue(test_idp.simple_verify_authn_response_ava(resp.ava, "testuser1"))