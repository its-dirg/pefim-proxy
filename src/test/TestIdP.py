import urllib
from saml2.sigver import encrypt_cert_from_item
from test.TestHelper import get_post_action_body
from saml2.authn_context import AuthnBroker, authn_context_class_ref
from saml2.authn_context import PASSWORD

__author__ = 'haho0032'
from saml2 import server, BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
import re


class Cache(object):
    def __init__(self):
        self.user2uid = {}
        self.uid2user = {}

def username_password_authn_dummy():
    return None



class TestIdP(object):

    USERS = {
        "testuser1": {
            "c": "SE",
            "displayName": "Hans Hoerberg",
            "eduPersonPrincipalName": "haho@example.com",
            "eduPersonScopedAffiliation": "staff@example.com",
            "eduPersonTargetedID": "one!for!all",
            "email": "hans@example.com",
            "givenName": "Hans",
            "initials": "P",
            "labeledURL": "http://www.example.com/haho My homepage",
            "norEduPersonNIN": "SE199012315555",
            "o": "Example Co.",
            "ou": "IT",
            "schacHomeOrganization": "example.com",
            "sn": "Hoerberg",
            "uid": "haho",
            "PVP-VERSION": "2.1",
            "PVP-PRINCIPALNAME": "Hoerberg",
            "PVP-PARTICIPANT-ID": "AT:TEST:1",
            "PVP-ROLES": "admin",
        },
        "testuser2": {
            "sn": "Testsson",
            "givenName": "Test",
            "eduPersonAffiliation": "student",
            "eduPersonScopedAffiliation": "student@example.com",
            "eduPersonPrincipalName": "test@example.com",
            "uid": "testuser1",
            "eduPersonTargetedID": "one!for!all",
            "c": "SE",
            "o": "Example Co.",
            "ou": "IT",
            "initials": "P",
            "schacHomeOrganization": "example.com",
            "email": "hans@example.com",
            "displayName": "Test Testsson",
            "labeledURL": "http://www.example.com/haho My homepage",
            "norEduPersonNIN": "SE199012315555"
        },

    }

    def __init__(self, conf_name=None):
        if conf_name is None:
            conf_name = "/Users/haho0032/Develop/github/pefim-proxy/src/test/external_config_test_idp"
        self.idp = server.Server(conf_name, cache=Cache())
        self.idp.ticket = {}
        self.authn_req = None
        self.binding_out = None
        self.destination = None

    #binding = BINDING_HTTP_REDIRECT or BINDING_HTTP_POST
    def handle_authn_request(self, saml_request, relay_state, binding, userid):

        self.authn_req = self.idp.parse_authn_request(saml_request, binding)
        _encrypt_cert = encrypt_cert_from_item(self.authn_req.message)

        self.binding_out, self.destination = self.idp.pick_binding(
                                                                    "assertion_consumer_service",
                                                                    bindings=None,
                                                                    entity_id=self.authn_req.message.issuer.text,
                                                                    request=self.authn_req.message)
        resp_args = self.idp.response_args(self.authn_req.message)
        AUTHN_BROKER = AuthnBroker()
        AUTHN_BROKER.add(authn_context_class_ref(PASSWORD),
                         username_password_authn_dummy,
                         10,
                         "http://test.idp.se")
        AUTHN_BROKER.get_authn_by_accr(PASSWORD)
        resp_args["authn"] = AUTHN_BROKER.get_authn_by_accr(PASSWORD)
        _resp = self.idp.create_authn_response(TestIdP.USERS[userid],
                                               userid=userid,
                                               encrypt_cert=_encrypt_cert,
                                               encrypt_assertion_self_contained=True,
                                               encrypted_advice_attributes=True,
                                               **resp_args)
        kwargs = {}
        http_args = self.idp.apply_binding(BINDING_HTTP_POST,
                                           "%s" % _resp,
                                           self.destination,
                                           relay_state,
                                           response=True,
                                           **kwargs)
        action, body = get_post_action_body(http_args["data"][3])
        return action, urllib.urlencode(body)

    def verify_authn_response_ava(self, ava, userid):
        data = TestIdP.USERS[userid]
        if ava is None or "uid" not in ava:
            return False
        for key in ava:
            if key not in data:
                return False
            value = ava[key]
            if isinstance(value, list):
                value = value[0]
            if data[key] != value:
                return False
        return True