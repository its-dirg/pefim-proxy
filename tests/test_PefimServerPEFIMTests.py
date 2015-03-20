from os import path

from saml2 import BINDING_HTTP_REDIRECT
from saml2.entity_category.at_egov_pvp2 import EGOVTOKEN, CHARGEATTR
from test import TestSp

from test.TestHelper import create_cookie_header, get_url_dict, get_post_action_body
from test.TestIdP import TestIdP
from test.TestSp import TestSp


__author__ = 'haho0032'

import cherrypy
import os
from cherrypy.test import helper
import pefim_server_conf_local
from beaker.middleware import SessionMiddleware
from pefimproxy.server import WsgiApplication
from argparse import Namespace


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


    def test_swamid_backend_idp(self):
        test_sp = TestSp(self.BASEDIR, conf_name=self.BASEDIR + "/external/pvp2_config_test_sp.py")
        url = test_sp.create_authn_request()
        self.getPage(url)
        self.assertStatus('303 See Other')
        req = get_url_dict(self.headers)
        self.assertTrue("SAMLRequest" in req)
        self.assertTrue("RelayState" in req)
        test_idp = TestIdP(self.BASEDIR, conf_name=self.BASEDIR + "/external/swamid_config_test_idp.py")
        action, body = test_idp.handle_authn_request(req["SAMLRequest"][0], req["RelayState"][0], BINDING_HTTP_REDIRECT,
                                                     "testuser1")
        cookies = create_cookie_header(self.cookies)
        self.getPage(action, headers=cookies, method='POST', body=body)
        action, body = get_post_action_body(self.body)
        self.assertStatus('200 OK')
        self.assertTrue('http://test.sp.se:8900/acs/post' == action, "Must be designated for the right SP!")
        resp = test_sp.eval_authn_response(body["SAMLResponse"])
        self.assertTrue(len(resp.ava) == 1)
        self.assertTrue("eduPersonTargetedID" in resp.ava)
        self.assertTrue(test_idp.simple_verify_authn_response_ava(resp.ava, "testuser1"))

    def test_pvp2(self):
        test_sp = TestSp(self.BASEDIR, conf_name=self.BASEDIR + "/external/pvp2_config_test_sp.py")
        url = test_sp.create_authn_request()
        self.getPage(url)
        self.assertStatus('303 See Other')
        req = get_url_dict(self.headers)
        self.assertTrue("SAMLRequest" in req)
        self.assertTrue("RelayState" in req)
        test_idp = TestIdP(self.BASEDIR, conf_name=self.BASEDIR + "/external/at_egov_pvp2_config_test_idp.py")
        action, body = test_idp.handle_authn_request(req["SAMLRequest"][0], req["RelayState"][0], BINDING_HTTP_REDIRECT,
                                                     "testuser3")
        cookies = create_cookie_header(self.cookies)
        self.getPage(action, headers=cookies, method='POST', body=body)
        action, body = get_post_action_body(self.body)
        self.assertStatus('200 OK')
        self.assertTrue('http://test.sp.se:8900/acs/post' == action, "Must be designated for the right SP!")
        resp = test_sp.eval_authn_response(body["SAMLResponse"])
        self.assertTrue(test_idp.simple_verify_authn_response_ava(resp.ava, "testuser3"))
        self.assertTrue(len(resp.ava) == len(EGOVTOKEN))
        _resp = {'uid': ['PVP-USERID'], 'PVP-ROLES': ['PVP-ROLES'], 'PVP-OU-OKZ': ['PVP-OU-OKZ'],
                 'PVP-PRINCIPAL-NAME': ['PVP-PRINCIPAL-NAME'], 'PVP-BIRTHDATE': ['PVP-BIRTHDATE'],
                 'telephoneNumber': ['PVP-TEL'], 'PVP-VERSION': ['PVP-VERSION'], 'PVP-BPK': ['PVP-BPK'],
                 'PVP-FUNCTION': ['PVP-FUNCTION'], 'PVP-GID': ['PVP-GID'], 'PVP-PARTICIPANT-ID': ['PVP-PARTICIPANT-ID'],
                 'PVP-PARTICIPANT-OKZ': ['PVP-PARTICIPANT-OKZ'], 'mail': ['PVP-MAIL'], 'ou': ['PVP-OU'],
                 'givenName': ['PVP-GIVENNAME'], 'PVP-OU-GV-OU-ID': ['PVP-OU-GV-OU-ID']}
        for key in _resp:
            self.assertTrue(key in resp.ava)
            self.assertTrue(resp.ava[key] == _resp[key])

    def test_pvp2charge(self):
        test_sp = TestSp(self.BASEDIR, conf_name=self.BASEDIR + "/external/pvp2charge_config_test_sp.py")
        url = test_sp.create_authn_request()
        self.getPage(url)
        self.assertStatus('303 See Other')
        req = get_url_dict(self.headers)
        self.assertTrue("SAMLRequest" in req)
        self.assertTrue("RelayState" in req)
        test_idp = TestIdP(self.BASEDIR, conf_name=self.BASEDIR + "/external/at_egov_pvp2_config_test_idp.py")
        action, body = test_idp.handle_authn_request(req["SAMLRequest"][0], req["RelayState"][0], BINDING_HTTP_REDIRECT,
                                                     "testuser3")
        cookies = create_cookie_header(self.cookies)
        self.getPage(action, headers=cookies, method='POST', body=body)
        action, body = get_post_action_body(self.body)
        self.assertStatus('200 OK')
        self.assertTrue('http://test.sp.se:8900/acs/post' == action, "Must be designated for the right SP!")
        resp = test_sp.eval_authn_response(body["SAMLResponse"])
        self.assertTrue(test_idp.simple_verify_authn_response_ava(resp.ava, "testuser3"))
        self.assertTrue(len(resp.ava) == len(CHARGEATTR))
        _resp = {'PVP-CHARGE-CODE': ['PVP-CHARGE-CODE'], 'PVP-INVOICE-RECPT-ID': ['PVP-INVOICE-RECPT-ID'],
                 'PVP-COST-CENTER-ID': ['PVP-COST-CENTER-ID']}
        for key in _resp:
            self.assertTrue(key in resp.ava)
            self.assertTrue(resp.ava[key] == _resp[key])