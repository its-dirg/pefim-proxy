from _util.TestSp import TestSp

__author__ = 'haho0032'

from os import path
import os

from saml2 import BINDING_HTTP_REDIRECT
import cherrypy
from cherrypy.test import helper
from beaker.middleware import SessionMiddleware
from argparse import Namespace

from _util.TestHelper import create_cookie_header, get_url_dict, get_post_action_body
from _util.TestIdP import TestIdP
import pefim_server_conf_default
from pefimproxy.server import WsgiApplication


class PefimServerSPTestCase(helper.CPWebCase):
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    ARGS = Namespace(debug=False,
                     entityid="http://test.idp.se:1111/TestIdP.xml",
                     config="pefim_proxy_conf_local",
                     server_config="pefim_server_conf_default")

    WSGI_APP = WsgiApplication(ARGS, base_dir=path.dirname(path.realpath(__file__)) + "/../")

    @staticmethod
    def application(environ, start_response):
        return PefimServerSPTestCase.WSGI_APP.run_server(environ, start_response)

    def setup_server():
        cherrypy.tree.graft(SessionMiddleware(PefimServerSPTestCase.application, pefim_server_conf_default.SESSION_OPTS),
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
        new_name_id = resp.assertion.subject.name_id.text
        tid2 = self.WSGI_APP.get_tid1(new_name_id)
        self.assertTrue(tid2['tid1'] == "testuser1", "Verify that tid1 is ok!")
        self.assertTrue(tid2['sp_entityid'] == "http://test.sp.se:8900/acs/post", "Verify that sp_entity is ok!")
        self.assertTrue(test_idp.simple_verify_authn_response_ava(resp.ava, "testuser1"))

        test_sp = TestSp(self.BASEDIR)
        url = test_sp.create_authn_request()
        self.getPage(url)
        req = get_url_dict(self.headers)
        test_idp = TestIdP(self.BASEDIR)
        action, body = test_idp.handle_authn_request(req["SAMLRequest"][0], req["RelayState"][0], BINDING_HTTP_REDIRECT,
                                                     "testuser1")
        cookies = create_cookie_header(self.cookies)
        self.getPage(action, headers=cookies, method='POST', body=body)
        action, body = get_post_action_body(self.body)
        resp = test_sp.eval_authn_response(body["SAMLResponse"])
        self.assertTrue(new_name_id == resp.assertion.subject.name_id.text, "No new NameId should be generated!")
