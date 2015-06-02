from saml2.response import StatusUnknownPrincipal
from _util.TestSp import TestSp
from tests import pefim_server_conf_default

__author__ = 'haho0032'

from os import path
import os
import cherrypy
from cherrypy.test import helper
from beaker.middleware import SessionMiddleware
from argparse import Namespace

from _util.TestHelper import get_post_action_body
from pefimproxy.server import WsgiApplication


class NoEntCatTest(helper.CPWebCase):
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    ARGS = Namespace(debug=False,
                     entityid="http://test.idp.se:1111/TestIdP.xml",
                     config="pefim_proxy_conf_local",
                     server_config="pefim_server_conf_default")

    WSGI_APP = WsgiApplication(ARGS, base_dir=path.dirname(path.realpath(__file__)) + "/../")

    @staticmethod
    def application(environ, start_response):
        return NoEntCatTest.WSGI_APP.run_server(environ, start_response)

    def setup_server():
        cherrypy.tree.graft(SessionMiddleware(NoEntCatTest.application, pefim_server_conf_default.SESSION_OPTS),
                            '/')
        pass

    setup_server = staticmethod(setup_server)


    def test_no_ent_cat_flow(self):
        test_sp = TestSp(self.BASEDIR, conf_name=self.BASEDIR + "/external/no_entity_category_config_test_sp.py")
        url = test_sp.create_authn_request()
        self.getPage(url)
        self.assertStatus('200 OK')
        action, body = get_post_action_body(self.body)
        self.assertTrue('http://test_no_ent_cat.sp.se:8900/acs/post' == action, "Must be designated for the right SP!")
        try:
            test_sp.eval_authn_response(body["SAMLResponse"])
            self.assertTrue(False, "Supposed to throw StatusUnknownPrincipal!")
        except StatusUnknownPrincipal as exc:
            self.assertTrue(exc.message == 'Entity category in metadata is not supported /samlp:EntityDescriptor'
                                           '/samlp:Extensions/samlp: EntityAttributes from urn:oasis:names:tc:SAML:2.0'
                                           ':status:Responder')
            pass
