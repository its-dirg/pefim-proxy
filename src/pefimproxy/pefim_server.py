import os
import sys
from os import path
import traceback
from cherrypy import wsgiserver
from cherrypy.wsgiserver import ssl_pyopenssl
from beaker.middleware import SessionMiddleware
from saml2.s_utils import exception_trace
from pefimproxy.server import WsgiApplication


def application(environ, start_response):
    return wsgi_app.run_server(environ, start_response)


def main():
    sys.path.insert(0, os.getcwd())

    args = WsgiApplication.arg_parser()

    pefim_server_conf = __import__(args.server_config)
    try:
        global wsgi_app
        wsgi_app = WsgiApplication(args, base_dir=os.getcwd() + "/")

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
    except Exception, excp:
        args = WsgiApplication.arg_parser(error="Invalid configuration in %s or %s, please consult the documentation."
                                                % (args.config, args.server_config),
                                          exception=" Exception:%s" % exception_trace(excp))

if __name__ == '__main__':
    main()