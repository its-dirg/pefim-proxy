from os import path

from saml2 import BINDING_HTTP_REDIRECT
from saml2.entity_category.at_egov_pvp2 import EGOVTOKEN, CHARGEATTR

from _util.TestHelper import create_cookie_header, get_url_dict, get_post_action_body
from _util.TestIdP import TestIdP
from _util.TestSp import TestSp


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
                     config="pefim_proxy_conf_local",
                     server_config="pefim_server_conf_local",
                     e_alg="aes_128_cbc",
                     key=os.urandom(16),
                     iv=os.urandom(16)
    )

    WSGI_APP = WsgiApplication(ARGS, base_dir=path.dirname(path.realpath(__file__)) + "/../")

    @staticmethod
    def application(environ, start_response):
        return PefimServerSPTests.WSGI_APP.run_server(environ, start_response)

    def setup_server():
        cherrypy.tree.graft(SessionMiddleware(PefimServerSPTests.application, pefim_server_conf_local.SESSION_OPTS),
                            '/')
        pass

    setup_server = staticmethod(setup_server)

    def test_swamid_backend_idp(self):
        global swamid_backend_idp_tid2
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
        tid2 = self.WSGI_APP.get_tid1(resp.assertion.subject.name_id.text)
        if 'swamid_backend_idp_tid2' in globals() and swamid_backend_idp_tid2 is not None:
            self.assertTrue(resp.assertion.subject.name_id.text == swamid_backend_idp_tid2, "A new tid2 should not be generated.")
        swamid_backend_idp_tid2 = resp.assertion.subject.name_id.text
        self.assertTrue(tid2['tid1'] == "testuser1", "Verify that tid1 is ok!")
        self.assertTrue(tid2['sp_entityid'] == "http://test.sp.se:8900/acs/post", "Verify that sp_entity is ok!")
        self.assertTrue(len(resp.ava) == 1)
        self.assertTrue("eduPersonTargetedID" in resp.ava)
        self.assertTrue(test_idp.simple_verify_authn_response_ava(resp.ava, "testuser1"))

    def test_swamid_backend_idp_cached(self):
        #The test should work to run twice when the user is cached.
        global swamid_backend_idp_tid2
        swamid_backend_idp_tid2 = None
        self.test_swamid_backend_idp()
        self.test_swamid_backend_idp()

    def test_pvp2(self):
        global pvp2_tid2
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
        tid2 = self.WSGI_APP.get_tid1(resp.assertion.subject.name_id.text)
        if 'pvp2_tid2' in globals() and pvp2_tid2 is not None:
            self.assertTrue(resp.assertion.subject.name_id.text == pvp2_tid2, "A new tid2 should not be generated.")
        pvp2_tid2 = resp.assertion.subject.name_id.text
        self.assertTrue(tid2['tid1'] == "testuser3", "Verify that tid1 is ok!")
        self.assertTrue(tid2['sp_entityid'] == "http://test.sp.se:8900/acs/post", "Verify that sp_entity is ok!")
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

    def test_pvp2_cached(self):
        global pvp2_tid2
        pvp2_tid2 = None
        #The test should work to run twice when the user is cached.
        self.test_pvp2()
        self.test_pvp2()


    def test_pvp2charge(self):
        global pvp2charge_tid2
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
        tid2 = self.WSGI_APP.get_tid1(resp.assertion.subject.name_id.text)
        if 'pvp2charge_tid2' in globals() and pvp2charge_tid2 is not None:
            self.assertTrue(resp.assertion.subject.name_id.text == pvp2charge_tid2, "A new tid2 should not be generated.")
        pvp2charge_tid2 = resp.assertion.subject.name_id.text
        self.assertTrue(tid2['tid1'] == "testuser3", "Verify that tid1 is ok!")
        self.assertTrue(tid2['sp_entityid'] == "http://test.sp.se:8900/acs/post", "Verify that sp_entity is ok!")
        self.assertTrue(test_idp.simple_verify_authn_response_ava(resp.ava, "testuser3"))
        self.assertTrue(len(resp.ava) == len(CHARGEATTR))
        _resp = {'PVP-CHARGE-CODE': ['PVP-CHARGE-CODE'], 'PVP-INVOICE-RECPT-ID': ['PVP-INVOICE-RECPT-ID'],
                 'PVP-COST-CENTER-ID': ['PVP-COST-CENTER-ID']}
        for key in _resp:
            self.assertTrue(key in resp.ava)
            self.assertTrue(resp.ava[key] == _resp[key])

    def test_pvp2charge_cached(self):
        #The test should work to run twice when the user is cached.
        global pvp2charge_tid2
        pvp2charge_tid2 = None
        self.test_pvp2charge()


    def test_pvp2charge_and_pvp2(self):
        #Call proxy from sp pvp2charge
        test_sp_pvp2charge = TestSp(self.BASEDIR, conf_name=self.BASEDIR + "/external/pvp2charge_config_test_sp.py")
        url = test_sp_pvp2charge.create_authn_request()
        self.getPage(url)
        req_pvp2charge = get_url_dict(self.headers)

        #Get response from underlying IdP at_egov_pvp2
        test_idp_pvp2charge = TestIdP(self.BASEDIR, conf_name=self.BASEDIR + "/external/at_egov_pvp2_config_test_idp."
                                                                             "py")
        action_pvp2charge, body_pvp2charge = test_idp_pvp2charge.handle_authn_request(
            req_pvp2charge["SAMLRequest"][0],
            req_pvp2charge["RelayState"][0],
            BINDING_HTTP_REDIRECT,
            "testuser3")
        cookies_pvp2charge = create_cookie_header(self.cookies)

        #Call proxy from sp pvp2
        test_sp_pvp2 = TestSp(self.BASEDIR, conf_name=self.BASEDIR + "/external/pvp2_config_test_sp.py")
        url = test_sp_pvp2.create_authn_request()
        self.getPage(url)
        req_pvp2 = get_url_dict(self.headers)

        #Get response from underlying IdP at_egov_pvp2
        test_idp_pvp2 = TestIdP(self.BASEDIR, conf_name=self.BASEDIR + "/external/at_egov_pvp2_config_test_idp.py")
        action_pvp2, body_pvp2 = test_idp_pvp2.handle_authn_request(req_pvp2["SAMLRequest"][0],
                                                                    req_pvp2["RelayState"][0],
                                                                    BINDING_HTTP_REDIRECT,
                                                                    "testuser3")
        cookies_pvp2 = create_cookie_header(self.cookies)

        #Get response from proxy for pvp2 call
        self.getPage(action_pvp2, headers=cookies_pvp2, method='POST', body=body_pvp2)
        action_pvp2, body_pvp2 = get_post_action_body(self.body)
        self.assertStatus('200 OK')
        resp = test_sp_pvp2.eval_authn_response(body_pvp2["SAMLResponse"])
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


        #Get response from proxy for pvp2charge call
        self.getPage(action_pvp2charge, headers=cookies_pvp2charge, method='POST', body=body_pvp2charge)
        action_pvp2charge, body_pvp2charge = get_post_action_body(self.body)
        self.assertStatus('200 OK')
        resp = test_sp_pvp2charge.eval_authn_response(body_pvp2charge["SAMLResponse"])
        self.assertTrue(len(resp.ava) == len(CHARGEATTR))
        _resp = {'PVP-CHARGE-CODE': ['PVP-CHARGE-CODE'], 'PVP-INVOICE-RECPT-ID': ['PVP-INVOICE-RECPT-ID'],
                 'PVP-COST-CENTER-ID': ['PVP-COST-CENTER-ID']}
        for key in _resp:
            self.assertTrue(key in resp.ava)
            self.assertTrue(resp.ava[key] == _resp[key])
