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


class TargetIdOnServerNoSubjectCacheTestCase(helper.CPWebCase):
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    ARGS = Namespace(debug=False,
                     entityid="http://test.idp.se:1111/TestIdP.xml",
                     config="pefim_proxy_conf_local",
                     server_config="pefim_server_conf_hash"
    )

    WSGI_APP = WsgiApplication(ARGS, base_dir=path.dirname(path.realpath(__file__)) + "/../")


    @staticmethod
    def application(environ, start_response):
        return TargetIdOnServerNoSubjectCacheTestCase.WSGI_APP.run_server(environ, start_response)

    def setup_server():
        cherrypy.tree.graft(SessionMiddleware(TargetIdOnServerNoSubjectCacheTestCase.application, pefim_server_conf_local.SESSION_OPTS),
                            '/')
        pass

    setup_server = staticmethod(setup_server)

    def test_pvp2(self):
        test_sp = TestSp(self.BASEDIR, conf_name=self.BASEDIR + "/external/pvp2_config_test_sp.py")
        url = test_sp.create_authn_request()
        self.getPage(url)
        req = get_url_dict(self.headers)
        test_idp = TestIdP(self.BASEDIR, conf_name=self.BASEDIR + "/external/at_egov_pvp2_config_test_idp.py")
        action, body = test_idp.handle_authn_request(req["SAMLRequest"][0], req["RelayState"][0], BINDING_HTTP_REDIRECT,
                                                     "testuser3")
        cookies = create_cookie_header(self.cookies)
        self.getPage(action, headers=cookies, method='POST', body=body)
        action, body = get_post_action_body(self.body)
        resp = test_sp.eval_authn_response(body["SAMLResponse"])
        tid1 = self.WSGI_APP.get_tid1(resp.assertion.subject.name_id.text)
        self.assertTrue(tid1 == "testuser3", "Verify that tid1 is ok!")
        tid2_hash = self.WSGI_APP.get_tid2("testuser3")
        self.assertTrue(tid2_hash == resp.assertion.subject.name_id.text, "Should be able to get tid2_enc from tid1.")

