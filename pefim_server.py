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
from pefimproxy.util.config import get_configurations
from pefimproxy.util.http import HttpHelper, Session
from saml2.authn_context import AuthnBroker, authn_context_class_ref, UNSPECIFIED


class start_response_intercept(object):

    def __init__(self, start_response):
        self.start_response = start_response

    def __call__(self, status, response_headers, exc_info=None):
        self.status = status
        self.response_headers = response_headers
        self.exc_info = exc_info
        self.start_response(status, response_headers, exc_info=None)


class WsgiApplication(object):

    def __init__(self, server_conf, args):
        self.cache = {}
        self.urls = [(r'.+\.css$', WsgiApplication.css),]
        self.sp_args = None
        self.base_dir = path.dirname(path.realpath(__file__)) + "/"
        self.logger = WsgiApplication.create_logger(server_conf.LOG_FILE, self.base_dir)
        # read the configuration file
        sys.path.insert(0, ".")
        config = importlib.import_module(args.config)
        # deal with metadata only once
        _metadata_conf = config.CONFIG["metadata"]
        _spc = config_factory("sp", args.config)
        mds = _spc.load_metadata(_metadata_conf)
        idp_conf, sp_confs = get_configurations(args.config, metadata_construction=False, metadata=mds, cache=self.cache)
        self.config = {
            "SP": sp_confs,
            "IDP": idp_conf}
        # If entityID is set it means this is a proxy in front of one IdP
        if args.entityid:
            self.entity_id = args.entityid
            self.sp_args = {}
        else:
            self.entity_id = None
            self.sp_args = {"discosrv": config.DISCO_SRV}
        
        sp = SamlSP(None, None, self.config["SP"], self.cache)
        self.urls.extend(sp.register_endpoints())
            
        self.idp = SamlIDP(None, None, self.config["IDP"], self.cache, None)
        self.urls.extend(self.idp.register_endpoints())

    @staticmethod
    def css(environ, start_response):
        try:
            info = open(environ["PATH_INFO"]).read()
            resp = Response(info)
        except (OSError, IOError):
            resp = NotFound(environ["PATH_INFO"])
    
        return resp(environ, start_response)
    
    @staticmethod
    def arg_parser(idpconfig=None, spconf=None):
        #Read arguments.
        parser = argparse.ArgumentParser()
        parser.add_argument('-d', dest='debug', action='store_true')
        parser.add_argument('-e', dest="entityid")
        parser.add_argument(dest="config")
        args = parser.parse_args()
        return args

    @staticmethod
    def create_logger(filename, base_dir):
        """
        Creates a logger with a given filename.
        :param filename: File name for the log
        :return: A logger class.
        """
        logger = logging.getLogger("")
        logfile_name = base_dir + filename
        handler = logging.FileHandler(logfile_name)
        base_formatter = logging.Formatter(
            "%(asctime)s %(name)s:%(levelname)s %(message)s")
        cpc = ('%(asctime)s %(name)s:%(levelname)s '
               '[%(client)s,%(path)s,%(cid)s] %(message)s')
        handler.setFormatter(base_formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        _formatter = logging.Formatter(cpc)
        fil_handler = logging.FileHandler(logfile_name)
        fil_handler.setFormatter(_formatter)

        buf_handler = BufferingHandler(10000)
        buf_handler.setFormatter(_formatter)
        return logger

    def incomming(self, info, instance, environ, start_response, relay_state):
        """
        An Authentication request has been requested, this is the second step
        in the sequence
    
        :param info: Information about the authentication request
        :param instance: IDP instance that received the Authentication request
        :param environ: WSGI environment
        :param start_response: WSGI start_response
        :param relay_state:
    
        :return: response
        """
    
        # If I know which IdP to authenticate at return a redirect to it
        calling_sp_entity_id = info["authn_req"].issuer.text
        inst = SamlSP(environ, start_response, self.config["SP"], self.cache, self.outgoing, calling_sp_entity_id,
                      **self.sp_args)
        if self.entity_id:
            state_key = inst.store_state(info["authn_req"], relay_state,
                                         info["req_args"])
            return inst.authn_request(self.entity_id, state_key, info["encrypt_cert"])
        else:
            # start the process by finding out which IdP to authenticate at
            return inst.disco_query(info["authn_req"], relay_state, info["req_args"])

    def outgoing(self, response, org_response, instance):
        """
        An authentication response has been received and now an authentication
        response from this server should be constructed.
    
        :param response: The Authentication response
        :param instance: SP instance that received the authentication response
        :return: response
        """
    
        _idp = SamlIDP(instance.environ, instance.start_response,
                       self.config["IDP"], self.cache, self.outgoing)
    
        _state = instance.sp.state[response.in_response_to]
        orig_authn_req, relay_state, req_args = instance.sp.state[_state]
    
        # The Subject NameID
        try:
            #TODO Must fix this so the subject/nameid is unencrypted
            subject = response.get_subject()
        except:
            pass

        resp_args = _idp.idp.response_args(orig_authn_req)
    
        # Slightly awkward, should be done better
        try:
            _authn_info = response.authn_info()[0]
            _authn = {"class_ref": _authn_info[0], "authn_auth": _authn_info[1][0]}
        except:
            _authn = None #Works for encrypted assertion

        identity = response.ava
        if identity is None and response.response.encrypted_assertion is not None:
            #Add dummy value
            identity = {"uid": "dummyuser"}

        # Will signed the response by default
        resp = _idp.construct_authn_response(identity, userid = "dummyuser",
                                             authn=_authn, name_id=None, resp_args=resp_args,
                                             relay_state=relay_state, sign_response=True,
                                             org_resp=response, org_xml_response=org_response)

        return resp

    def run_entity(self, spec, environ, start_response):
        """
        Picks entity and method to run by that entity.

        :param spec: a tuple (entity_type, response_type, binding)
        :param environ: WSGI environ
        :param start_response: WSGI start_response
        :return:
        """

        if isinstance(spec, tuple):
            if spec[0] == "SP":
                inst = SamlSP(environ, start_response, self.config["SP"], self.cache,
                              self.outgoing, sp_key=spec[3], **self.sp_args)
                param = spec[2:3]
            else:
                inst = SamlIDP(environ, start_response, self.config["IDP"], self.cache,
                               self.incomming)
                param = spec[2:]

            func = getattr(inst, spec[1])
            return func(*param)
        else:
            return spec()

    def run_server(self, environ, start_response):
        """
        WSGI application. Handles all requests.
        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: Depends on the request. Always a WSGI response where start_response first have to be initialized.
        """
        try:
            start_response = start_response_intercept(start_response)
            session = Session(environ)

            path = environ.get('PATH_INFO', '').lstrip('/')
            HttpHelper.log_request(environ, path, self.logger)
            response = None

            for regex, spec in self.urls:
                match = re.search(regex, path)
                if match is not None:
                    try:
                        environ['oic.url_args'] = match.groups()[0]
                    except IndexError:
                        environ['oic.url_args'] = path

                    response = self.run_entity(spec, environ, start_response)
                    break

            try:
                return HttpHelper.handle_static(path, self.base_dir, start_response, self.logger)
            except Exception, excp:
                pass

            if response is None:
                response = NotFound()
            self.logger.info("response:")
            self.logger.info(response)
            return response(environ, start_response)
        except Exception, excp:
            urn = str(uuid4().urn)
            self.logger.error("uuid: " + urn + str(exception_trace(excp)))
            resp = ServiceError(urn)
            return resp(environ, start_response)


def application(environ, start_response):
    return wsgi_app.run_server(environ, start_response)

if __name__ == '__main__':
    args = WsgiApplication.arg_parser()

    global wsgi_app
    wsgi_app = WsgiApplication(pefim_server_conf, args)

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
