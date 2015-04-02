from _util.TestHelper import get_url_dict

__author__ = 'haho0032'

import cherrypy
from cherrypy.test import helper
import pefim_server_conf_local
from beaker.middleware import SessionMiddleware
from pefimproxy.server import WsgiApplication
from argparse import Namespace
from os import path
from _util.TestSp import TestSp
import urllib
import re

class DiscoTestCase(helper.CPWebCase):
    BASEDIR = path.abspath(path.dirname(__file__))
    ARGS = Namespace(debug=False,
                     entityid=None,
                     config="pefim_proxy_conf_local",
                     server_config="pefim_server_conf_local")

    WSGI_APP = WsgiApplication(ARGS, base_dir=path.dirname(path.realpath(__file__)) +
                                                                       "/../")

    @staticmethod
    def application(environ, start_response):
        return DiscoTestCase.WSGI_APP.run_server(environ, start_response)

    def setup_server():
        cherrypy.tree.graft(SessionMiddleware(DiscoTestCase.application, pefim_server_conf_local.SESSION_OPTS), '/')

    setup_server = staticmethod(setup_server)

    def test_discovery(self):
        test_sp = TestSp(self.BASEDIR, conf_name=self.BASEDIR + "/external/pvp2_config_test_sp.py")
        url = test_sp.create_authn_request()
        self.getPage(url)
        self.assertStatus('303 See Other')
        req = get_url_dict(self.headers)
        self.assertTrue("entityID" in req)
        self.assertTrue("return" in req)
        self.assertTrue(req["entityID"] == ['https://localhost:8999/pvp2_spproxy.xml'])
        returnIDParam = "entityID"
        if "returnIDParam" in req:
            returnIDParam = req["returnIDParam"][0]
        url = req["return"][0] + "&" + urllib.urlencode({returnIDParam: "http://test.idp.se:1111/TestIdP.xml"})
        self.getPage(url)
        self.assertStatus('303 See Other')
        location = None
        for header in self.headers:
            if "location" == header[0]:
                location = header[1]
        self.assertTrue(location is not None)
        res = re.match("^http://test.idp.se:1111(.*)$", location)
        self.assertTrue(res is not None)
        req = get_url_dict(self.headers)
        self.assertTrue("SAMLRequest" in req)
        self.assertTrue("RelayState" in req)

