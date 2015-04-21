#!/usr/bin/env python
import logging
from urlparse import urlparse
from saml2 import class_name
from saml2.httputil import ServiceError
from saml2.httputil import Response
from saml2.httputil import Redirect
from saml2.httputil import Unauthorized
from saml2.ident import IdentDB
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.server import Server
from saml2.sigver import encrypt_cert_from_item, pre_signature_part
import service

logger = logging.getLogger(__name__)

class SamlIDP(service.Service):
    def __init__(self, environ, start_response, conf, cache, incomming, tid1_to_tid2, tid2_to_tid1, 
                 encmsg_to_iv, tid_handler, force_persistant_nameid, force_no_userid_subject_cacheing, idp=None):
        """
        Constructor for the class.
        :param environ: WSGI environ
        :param start_response: WSGI start response function
        :param conf: The SAML configuration
        :param cache: Cache with active sessions
        """
        service.Service.__init__(self, environ, start_response)
        self.response_bindings = None
        if idp is None:
            self.idp = Server(config=conf, cache=cache)
        else:
            self.idp = idp
        self.incomming = incomming
        self.tid1_to_tid2 = tid1_to_tid2
        self.tid2_to_tid1 = tid2_to_tid1
        self.encmsg_to_iv = encmsg_to_iv
        self.tid_handler = tid_handler
        self.force_persistant_nameid = force_persistant_nameid
        self.force_no_userid_subject_cacheing = force_no_userid_subject_cacheing

    def verify_request(self, query, binding):
        """ Parses and verifies the SAML Authentication Request

        :param query: The SAML authn request, transport encoded
        :param binding: Which binding the query came in over
        :returns: dictionary
        """

        if not query:
            logger.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return {"response": resp}

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
            return resp
        except UnsupportedBinding as excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp

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

    def get_tid1_resp(self, org_resp):
        tid1 = org_resp.assertion.subject.name_id.text
        return tid1

    def get_sp_entityid(self, resp_args):
        sp_entityid = resp_args["destination"]
        return sp_entityid

    def get_tid2_enc(self, tid1, sp_entityid):
        iv = None
        if self.encmsg_to_iv is not None:
            iv = self.tid_handler.get_new_iv()
        tid2_enc = self.tid_handler.tid2_encrypt(tid1, sp_entityid, iv=iv)
        if self.encmsg_to_iv is not None:
            self.encmsg_to_iv[tid2_enc] = iv
        return tid2_enc

    def get_tid2_hash(self, tid1, sp_entityid):
        tid2_hash = self.tid_handler.tid2_hash(tid1, sp_entityid)
        return tid2_hash

    def handle_tid(self, tid1, tid2):
        if self.tid1_to_tid2 is not None:
            self.tid1_to_tid2[tid1] = tid2
        if self.tid2_to_tid1 is not None:
            self.tid2_to_tid1[tid2] = tid1

    def name_id_exists(self, userid, name_id_policy, sp_entity_id):
        try:
            snq = name_id_policy.sp_name_qualifier
        except AttributeError:
            snq = sp_entity_id

        if not snq:
            snq = sp_entity_id

        kwa = {"sp_name_qualifier": snq}

        try:
            kwa["format"] = name_id_policy.format
        except AttributeError:
            pass
        return self.idp.ident.find_nameid(userid, **kwa)

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

        sp_entityid = self.get_sp_entityid(resp_args)
        tid1 = self.get_tid1_resp(org_resp)
        userid = self.tid_handler.uid_hash(tid1)

        if self.force_no_userid_subject_cacheing:
            self.idp.ident = IdentDB({})

        name_id_exist = False
        if self.name_id_exists(userid, resp_args["name_id_policy"], resp_args["sp_entity_id"]):
            name_id_exist = True

        if not name_id_exist:
            if identity is not None:
                identity["uid"] = userid
            if self.tid2_to_tid1 is None:
                tid2 = self.get_tid2_enc(tid1, sp_entityid)
            else:
                tid2 = self.get_tid2_hash(tid1, sp_entityid)
        else:
            tid2 = None

        if self.force_persistant_nameid:
            if "name_id_policy" in resp_args:
                resp_args["name_id_policy"].format = NAMEID_FORMAT_PERSISTENT

        _resp = self.idp.create_authn_response(identity, userid=userid, name_id=name_id,
                                               authn=authn,
                                               sign_response=False,
                                               **resp_args)

        if not name_id_exist:
            #Fix for name_id so sid2 is used instead.
            _resp.assertion.subject.name_id.text = tid2
            self.idp.ident.remove_local(userid)
            self.idp.ident.store(userid, _resp.assertion.subject.name_id)

        tid2 = _resp.assertion.subject.name_id.text
        if self.tid2_to_tid1 is not None:
            self.tid2_to_tid1[tid2] = tid1
            if self.tid1_to_tid2 is not None:
                self.tid1_to_tid2[tid1] = tid2

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
