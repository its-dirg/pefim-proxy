import logging
import re
from logging.handlers import BufferingHandler
from uuid import uuid4
import importlib
import sys
from os import path
import os

from saml2.config import config_factory
from saml2.httputil import NotFound, ServiceError
from saml2.httputil import Response
import argparse
from saml2.s_utils import exception_trace

from pefimproxy.back import SamlSP
from pefimproxy.front import SamlIDP
from pefimproxy.util.config import get_configurations
from pefimproxy.util.http import HttpHelper, Session


class start_response_intercept(object):
    def __init__(self, start_response):
        self.start_response = start_response

    def __call__(self, status, response_headers, exc_info=None):
        self.status = status
        self.response_headers = response_headers
        self.exc_info = exc_info
        self.start_response(status, response_headers, exc_info=None)


class WsgiApplication(object, ):
    def __init__(self, args, base_dir):
        sys.path.insert(0, os.getcwd())
        server_conf = importlib.import_module(args.server_config)
        self.cache = {}
        self.urls = [(r'.+\.css$', WsgiApplication.css), ]
        self.sp_args = None
        self.base_dir = base_dir
        self.logger = WsgiApplication.create_logger(server_conf.LOG_FILE, self.base_dir)
        # read the configuration file
        config = importlib.import_module(args.config)
        # deal with metadata only once
        _metadata_conf = config.CONFIG["metadata"]
        _spc = config_factory("sp", args.config)
        mds = _spc.load_metadata(_metadata_conf)
        idp_conf, sp_confs = get_configurations(args.config, metadata_construction=False, metadata=mds,
                                                cache=self.cache)
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

        self.name_id_org_new = server_conf.NAME_ID_ORG_NEW
        self.name_ide_new_org = server_conf.NAME_ID_NEW_ORG

        self.idp = SamlIDP(None, None, self.config["IDP"], self.cache, None,
                           self.name_id_org_new, self.name_ide_new_org)
        self.urls.extend(self.idp.register_endpoints())

    def get_name_id_org(self, name_id_new):
        return self.name_ide_new_org[name_id_new]

    def get_name_id_new(self, name_id_org):
        return self.name_id_org_new[name_id_org]

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
        parser.add_argument(dest="server_config")
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
        if inst.sp_error_resp is not None:
            return inst.sp_error_resp
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
                       self.config["IDP"], self.cache, self.outgoing, self.name_id_org_new, self.name_ide_new_org)

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
            _authn = None  #Works for encrypted assertion

        identity = response.ava
        if identity is None and response.response.encrypted_assertion is not None:
            #Add dummy value
            identity = {"uid": "dummyuser"}

        # Will signed the response by default
        resp = _idp.construct_authn_response(identity, userid="dummyuser",
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
                               self.incomming, self.name_id_org_new, self.name_ide_new_org)
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

