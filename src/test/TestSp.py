import uuid
from saml2.cert import OpenSSLWrapper
from saml2.extension.pefim import SPCertEnc
from saml2.s_utils import rndstr, sid

__author__ = 'haho0032'

from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST, BINDING_HTTP_ARTIFACT, element_to_extension_element
from saml2.client import Saml2Client
from saml2 import s_utils
from saml2.md import Extensions
import xmldsig
import os

BASEDIR = os.path.abspath(os.path.dirname(__file__))

class TestSp(object):
    def __init__(self, conf_name=None):
        if conf_name is None:
            conf_name = BASEDIR + "/external_config_test_sp"
        self.sp = Saml2Client(config_file="%s" % conf_name)
        self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST, BINDING_HTTP_ARTIFACT]
        self.rstate = None
        self.msg_str = None
        self.sid = None
        self.ht_args = None
        self.entity_id = None
        self.cert_str = None
        self.cert_key_str = None
        self.outstanding_certs = {}
        self.outstanding_queries = {}

    @staticmethod
    def generate_cert():
        sn = uuid.uuid4().urn
        cert_info = {
            "cn": "localhost",
            "country_code": "se",
            "state": "ac",
            "city": "Umea",
            "organization": "ITS",
            "organization_unit": "DIRG"
        }
        osw = OpenSSLWrapper()
        ca_cert_str = osw.read_str_from_file(BASEDIR + "/root_cert/localhost.ca.crt")
        ca_key_str = osw.read_str_from_file(BASEDIR + "/root_cert/localhost.ca.key")
        req_cert_str, req_key_str = osw.create_certificate(cert_info, request=True, sn=sn, key_length=2048)
        cert_str = osw.create_cert_signed_certificate(ca_cert_str, ca_key_str, req_cert_str)
        return cert_str, req_key_str

    def create_authn_request(self):
        try:
            #sid_ = sid()
            #self.outstanding_queries[sid_] = came_from
            idps = self.sp.metadata.with_descriptor("idpsso")
            if len(idps) == 1:
                self.entity_id = idps.keys()[0]
            elif len(idps) > 1:
                raise Exception("TestSp only supports 1 idp in the metadata!")
            else:
                Exception("No IdP metadata found!")

            _binding, destination = self.sp.pick_binding("single_sign_on_service", self.bindings, "idpsso",
                                                         entity_id=self.entity_id)

            self.cert_str, self.cert_key_str = self.generate_cert()
            cert = {
                        "cert": self.cert_str,
                        "key": self.cert_key_str
                    }
            spcertenc = SPCertEnc(
                x509_data=xmldsig.X509Data(x509_certificate=xmldsig.X509Certificate(text=self.cert_str)))
            extensions = Extensions(extension_elements=[element_to_extension_element(spcertenc)])

            try:
                vorg_name = self.sp.vorg._name
            except AttributeError:
                vorg_name = ""

            if self.sp.authn_requests_signed:
                self.sid = s_utils.sid()
                req_id, self.msg_str = self.sp.create_authn_request(destination, vorg=vorg_name,
                                                                    sign=self.sp.authn_requests_signed,
                                                                    message_id=self.sid,
                                                                    extensions=extensions)
                self.sid = req_id
            else:
                req_id, req = self.sp.create_authn_request(destination, vorg=vorg_name, sign=False)
                self.msg_str = "%s" % req
                self.sid = req_id

            if cert is not None:
                self.outstanding_certs[self.sid] = cert

            self.rstate = rndstr()
            self.ht_args = self.sp.apply_binding(_binding, self.msg_str, destination, relay_state=self.rstate)
            url = self.ht_args["headers"][0][1]

        except Exception, exc:
            raise Exception("Failed to construct the AuthnRequest: %s" % exc)

        return url

    def eval_authn_response(self, saml_response, binding=BINDING_HTTP_POST):

        authresp = self.sp.parse_authn_request_response(
            saml_response, binding, self.outstanding_queries,
            self.outstanding_certs)
        return authresp
