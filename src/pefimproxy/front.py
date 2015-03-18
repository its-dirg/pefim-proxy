#!/usr/bin/env python
import logging
from urlparse import urlparse
from saml2 import class_name
from saml2.httputil import ServiceError
from saml2.httputil import Response
from saml2.httputil import Redirect
from saml2.httputil import Unauthorized
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.server import Server
from saml2.sigver import encrypt_cert_from_item, pre_signature_part
import service

logger = logging.getLogger(__name__)

class SamlIDP(service.Service):
    def __init__(self, environ, start_response, conf, cache, incomming):
        """
        Constructor for the class.
        :param environ: WSGI environ
        :param start_response: WSGI start response function
        :param conf: The SAML configuration
        :param cache: Cache with active sessions
        """
        service.Service.__init__(self, environ, start_response)
        self.response_bindings = None
        self.idp = Server(config=conf, cache=cache)
        self.incomming = incomming

    def verify_request(self, query, binding):
        """ Parses and verifies the SAML Authentication Request

        :param query: The SAML authn request, transport encoded
        :param binding: Which binding the query came in over
        :returns: dictionary
        """

        if not query:
            logger.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return {"response": resp(self.environ, self.start_response)}

        req_info = self.idp.parse_authn_request(query, binding)
        encrypt_cert = encrypt_cert_from_item(req_info.message)

        logger.info("parsed OK")
        _authn_req = req_info.message
        logger.debug("%s" % _authn_req)

        # Check that I know where to send the reply to
        try:
            binding_out, destination = self.idp.pick_binding(
                "assertion_consumer_service",
                bindings=self.response_bindings,
                entity_id=_authn_req.issuer.text, request=_authn_req)
        except Exception as err:
            logger.error("Couldn't find receiver endpoint: %s" % err)
            raise

        logger.debug("Binding: %s, destination: %s" % (binding_out,
                                                       destination))

        resp_args = {}
        try:
            resp_args = self.idp.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal as excp:
            _resp = self.idp.create_error_response(_authn_req.id,
                                                   destination, excp)
        except UnsupportedBinding as excp:
            _resp = self.idp.create_error_response(_authn_req.id,
                                                   destination, excp)

        req_args = {}
        for key in ["subject", "name_id_policy", "conditions",
                    "requested_authn_context", "scoping", "force_authn",
                    "is_passive"]:
            try:
                val = getattr(_authn_req, key)
            except AttributeError:
                pass
            else:
                if val is not None:
                    req_args[key] = val

        return {"resp_args": resp_args, "response": _resp,
                "authn_req": _authn_req, "req_args": req_args, "encrypt_cert": encrypt_cert}

    def handle_authn_request(self, binding_in):
        """
        Deal with an authentication request

        :param binding_in: Which binding was used when receiving the query
        :return: A response if an error occurred or session information in a
            dictionary
        """

        _request = self.unpack(binding_in)
        _binding_in = service.INV_BINDING_MAP[binding_in]

        try:
            _dict = self.verify_request(_request["SAMLRequest"], _binding_in)
        except UnknownPrincipal as excp:
            logger.error("UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding as excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)

        _binding = _dict["resp_args"]["binding"]
        if _dict["response"]:  # An error response
            http_args = self.idp.apply_binding(
                _binding, "%s" % _dict["response"],
                _dict["resp_args"]["destination"],
                _request["RelayState"], response=True)

            logger.debug("HTTPargs: %s" % http_args)
            return self.response(_binding, http_args)
        else:
            return self.incomming(_dict, self, self.environ,
                                  self.start_response, _request["RelayState"])

    def construct_authn_response(self, identity, userid, authn, resp_args,
                                 relay_state, name_id=None, sign_response=True, org_resp=None, org_xml_response=None):
        """

        :param identity:
        :param name_id:
        :param authn:
        :param resp_args:
        :param relay_state:
        :param sign_response:
        :return:
        """
        _resp = self.idp.create_authn_response(identity, userid=userid, name_id=name_id,
                                               authn=authn,
                                               sign_response=False,
                                               **resp_args)

        #TODO GET NAME_ID FROM org_resp.response.assertion and save to a db.
        advice = None
        for tmp_assertion in org_resp.response.assertion:
            if tmp_assertion.advice is not None:
                advice = tmp_assertion.advice
                break
        if advice is not None:
            _resp.assertion.advice = advice
        #_resp.assertion = []

        if sign_response:
            _class_sign = class_name(_resp)
            _resp.signature = pre_signature_part(_resp.id, self.idp.sec.my_cert, 1)
            _resp = self.idp.sec.sign_statement(_resp, _class_sign, node_id=_resp.id)
        http_args = self.idp.apply_binding(
            resp_args["binding"], "%s" % _resp, resp_args["destination"],
            relay_state, response=True)

        logger.debug("HTTPargs: %s" % http_args)

        resp = None
        if http_args["data"]:
            resp = Response(http_args["data"], headers=http_args["headers"])
        else:
            for header in http_args["headers"]:
                if header[0] == "Location":
                    resp = Redirect(header[1])

        if not resp:
            resp = ServiceError("Don't know how to return response")

        return resp

    def register_endpoints(self):
        """
        Given the configuration, return a set of URL to function mappings.
        """
        url_map = []
        for endp, binding in self.idp.config.getattr("endpoints", "idp")[
                "single_sign_on_service"]:
            p = urlparse(endp)
            url_map.append(("^%s/(.*)$" % p.path[1:],
                            ("IDP", "handle_authn_request",
                             service.BINDING_MAP[binding])))
            url_map.append(("^%s$" % p.path[1:],
                            ("IDP", "handle_authn_request",
                             service.BINDING_MAP[binding])))

        return url_map
