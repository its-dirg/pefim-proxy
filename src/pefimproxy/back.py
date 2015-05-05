#!/usr/bin/env python
import logging
import time
from saml2.saml import NAMEID_FORMAT_PERSISTENT
import xmldsig

from urlparse import urlparse
from saml2.extension.pefim import SPCertEnc
from saml2.md import Extensions
from saml2 import BINDING_HTTP_REDIRECT, element_to_extension_element
from saml2 import BINDING_HTTP_POST
from saml2.client_base import Base
from saml2.httputil import geturl
from saml2.httputil import ServiceError
from saml2.httputil import SeeOther
from saml2.httputil import Unauthorized
from saml2.response import VerificationError, AuthnResponse
from saml2.s_utils import UnknownPrincipal, MissingValue, Unsupported, OtherError
from saml2.s_utils import UnsupportedBinding

from service import BINDING_MAP
import service

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
#  Authentication request constructor
# -----------------------------------------------------------------------------


class SamlSP(service.Service):
    def __init__(self, environ, start_response, config, cache=None,
                 outgoing=None, calling_sp_entity_id=None, sp_key=None, discosrv=None, bindings=None,
                 force_persistant_nameid=None):
        service.Service.__init__(self, environ, start_response)
        self.sp_dict = {}
        self.sp = None
        ent_cat = None
        self.force_persistant_nameid = force_persistant_nameid
        self.sp_error_resp = None
        if sp_key is not None:
            self.sp = Base(config[sp_key]["config"], state_cache=cache)
        else:
            for key in config:
                tmp_conf = config[key]
                if calling_sp_entity_id is not None and ent_cat is None:
                    try:
                        ent_cat = set(tmp_conf["config"].metadata.entity_categories(calling_sp_entity_id))
                    except KeyError:
                        logger.error("SP's metadata MUST contain an EntityDescriptor to define requested attributes. "
                                     "Entityid=%s" % calling_sp_entity_id)
                        raise OtherError("Metadata is missing element /samlp:EntityDescriptor/samlp:Extensions/samlp:"
                                     "EntityAttributes")
                if key != "default" and set(tmp_conf["config"].entity_category) == ent_cat:
                    self.sp = Base(tmp_conf["config"], state_cache=cache)
                    break
                elif ent_cat is None:
                    self.sp_dict[key] = Base(tmp_conf["config"], state_cache=cache)
        if self.sp is None and (sp_key is not None or calling_sp_entity_id is not None):
            if "default" in config:
                self.sp = Base(config["default"]["config"], state_cache=cache)
            else:
                logger.error("UnsupportedBinding: %s" % (ent_cat,))
                raise OtherError("Entity category in metadata is not supported /samlp:EntityDescriptor/"
                                   "samlp:Extensions/samlp: EntityAttributes")
        #self.sp = Base(config, state_cache=cache)
        self.environ = environ
        self.start_response = start_response
        self.cache = cache
        self.idp_query_param = "entityID"
        self.outgoing = outgoing
        self.discosrv = discosrv
        if bindings:
            self.bindings = bindings
        else:
            self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
        logger.debug("--- SSO ---")

    def disco_response(self, *args):
        """
        If I got a useful response from the discovery server, continue with
        the authentication request.

        :return: redirect containing the authentication request
        """
        info = self.unpack_redirect()

        try:
            entity_id = info[self.idp_query_param]
        except KeyError:
            resp = Unauthorized("You must chose an IdP")
            return resp
        else:
            # should I check the state variable ?
            return self.authn_request(entity_id, info["state"])

    def store_state(self, authn_req, relay_state, req_args):
        # Which page was accessed to get here
        came_from = geturl(self.environ)
        key = "%i" % hash(came_from+self.environ["REMOTE_ADDR"]+str(time.time()))
        logger.debug("[sp.challenge] RelayState >> '%s'" % came_from)
        self.cache[key] = (authn_req, relay_state, req_args)
        return key

    def disco_query(self, authn_req, relay_state, req_args):
        """
        This service is expected to always use a discovery service. This is
        where the response is handled

        :param authn_req: The Authentication Request
        :return: A 302 messages redirecting to the discovery service
        """

        state_key = self.store_state(authn_req, relay_state, req_args)

        _cli = self.sp

        eid = _cli.config.entityid
        # returns list of 2-tuples
        dr = _cli.config.getattr("endpoints", "sp")["discovery_response"]
        # The first value of the first tuple is the one I want
        ret = dr[0][0]
        # append it to the disco server URL
        ret += "?state=%s" % state_key
        loc = _cli.create_discovery_service_request(self.discosrv, eid,
                                                    **{"return": ret,
                                                       "returnIDParam": self.idp_query_param})

        return SeeOther(loc)

    def authn_request(self, entity_id, state_key, encrypt_cert=None):
        _cli = self.sp
        req_args = self.cache[state_key][2]

        try:
            # Picks a binding to use for sending the Request to the IDP
            _binding, destination = _cli.pick_binding(
                "single_sign_on_service", self.bindings, "idpsso",
                entity_id=entity_id)
            logger.debug("binding: %s, destination: %s" % (_binding,
                                                           destination))
            # Binding here is the response binding that is which binding the
            # IDP should use to return the response.
            acs = _cli.config.getattr("endpoints", "sp")[
                "assertion_consumer_service"]
            # just pick one
            endp, return_binding = acs[0]

            if self.force_persistant_nameid:
                if "name_id_policy" in req_args:
                    req_args["name_id_policy"].format = NAMEID_FORMAT_PERSISTENT
                else:
                    req_args["nameid_format"] = NAMEID_FORMAT_PERSISTENT

            if encrypt_cert is not None:
                encrypt_cert = encrypt_cert.replace("-----BEGIN CERTIFICATE-----\n", "")
                encrypt_cert = encrypt_cert.replace("\n-----END CERTIFICATE-----\n", "")
                encrypt_cert = encrypt_cert.replace("\n-----END CERTIFICATE-----", "")
                spcertenc = SPCertEnc(x509_data=xmldsig.X509Data(x509_certificate=xmldsig.X509Certificate(
                    text=encrypt_cert)))
                extensions = Extensions(extension_elements=[element_to_extension_element(spcertenc)])
                req_id, req = _cli.create_authn_request(destination,
                                                        binding=return_binding,
                                                        extensions=extensions,
                                                        **req_args)
            else:
                req_id, req = _cli.create_authn_request(destination,
                                                        binding=return_binding,
                                                        **req_args)

            ht_args = _cli.apply_binding(_binding, "%s" % req, destination,
                                         relay_state=state_key)
            _sid = req_id
            logger.debug("ht_args: %s" % ht_args)
        except Exception, exc:
            logger.exception(exc)
            resp = ServiceError(
                "Failed to construct the AuthnRequest: %s" % exc)
            return resp

        # remember the request
        self.cache[_sid] = state_key
        resp = self.response(_binding, ht_args)
        return resp

    def authn_response(self, binding):
        """
        :param binding: Which binding the query came in over
        :returns: Error response or a response constructed by the transfer
            function
        """

        binding = service.INV_BINDING_MAP[binding]

        _authn_response = self.unpack(binding)

        if not _authn_response["SAMLResponse"]:
            logger.info("Missing Response")
            resp = Unauthorized('Unknown user')
            return resp

        try:
            _response = self.sp.parse_authn_request_response(_authn_response["SAMLResponse"], binding, self.cache,
                                                             decrypt=False)
        except UnknownPrincipal, excp:
            logger.error("UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp
        except UnsupportedBinding, excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp
        except VerificationError, err:
            resp = ServiceError("Verification error: %s" % (err,))
            return resp
        except Exception, err:
            resp = ServiceError("Other error: %s" % (err,))
            return resp

        org_xml_response = self.sp.unravel(_authn_response["SAMLResponse"], binding, AuthnResponse.msgtype)

        return self.outgoing(_response, org_xml_response, self)

    def register_endpoints(self):
        """
        Given the configuration, return a set of URL to function mappings.
        """

        url_map = []
        for key in self.sp_dict:
            sp = self.sp_dict[key]
            for endp, binding in sp.config.getattr("endpoints", "sp")[
                    "assertion_consumer_service"]:
                p = urlparse(endp)
                url_map.append(("^%s?(.*)$" % p.path[1:], ("SP", "authn_response",
                                                           BINDING_MAP[binding], key)))
                url_map.append(("^%s$" % p.path[1:], ("SP", "authn_response",
                                                      BINDING_MAP[binding], key)))

            for endp, binding in sp.config.getattr("endpoints", "sp")[
                    "discovery_response"]:
                p = urlparse(endp)
                #url_map.append(("^%s\?(.*)$" % p.path[1:], ("SP", "disco_response", BINDING_MAP[binding], key)))
                url_map.append(("^%s(.*)$" % p.path[1:], ("SP", "disco_response", BINDING_MAP[binding], key)))

        return url_map

if __name__ == "__main__":
    import sys
    from saml2.config import config_factory

    _config = config_factory("sp", sys.argv[1])
    sp = SamlSP(None, None, _config)
    maps = sp.register_endpoints()
    print maps