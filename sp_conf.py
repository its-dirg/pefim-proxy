#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from dirg_util.dict import Sqllite3Dict
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI
from saml2.entity_category.edugain import COC
from saml2.entity_category.swamid import RESEARCH_AND_EDUCATION
from saml2.entity_category.swamid import HEI
from saml2.entity_category.swamid import SFS_1993_1153
from saml2.entity_category.swamid import NREN
from saml2.entity_category.swamid import EU

#Setup to get the right path for xmlsec.
import server_conf

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None
if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin", "/usr/local/bin"])
else:
    xmlsec_path = '/usr/local/bin/xmlsec1'

#Url to a discovery server for SAML. None implies not using one.
DISCOSRV = "http://130.239.201.5/role/idp.ds"
#Url to a wayf for SAML. None implies not using one.
WAYF = None

#Changes should be performed in server_conf.py.
PORT = server_conf.PORT
HTTPS = server_conf.HTTPS
HOST = server_conf.HOST
BASEURL = server_conf.BASEURL

#Full URL to the SP.
ISSUER = "%s:%s" % (BASEURL, PORT)
BASE = ISSUER

#Discovery endpoint
DISCOENDPOINT = "disco"

#The base url for the SP at the server.
SPVERIFYBASE = "spverify"

#The base url for verification of the response from a IdP.
SPVERIFYBASEIDP = "idpspverify"

#The BASE url where the Idp performs the redirect after a authn request from the SP.
#For the cookies to work do not use subfolders.
ASCREDIRECT = 'acsredirect'
#The BASE url where the Idp performs a post after a authn request from the SP.
#For the cookies to work do not use subfolders.
ASCPOST = 'acspost'

#Regual expression to match a post from Idp to SP.
ASCVERIFYPOSTLIST = [ASCPOST + "/(.*)$", ASCPOST + "$"]
#Regual expression to match a redirect from Idp to SP.
ASCVERIFYREDIRECTLIST = [ASCREDIRECT + "/(.*)$", ASCREDIRECT + "$"]

#Must point to the complete path on disk to this file!
#Needed by the script create_metadata.sh and the SP to find all configurations.
#No need to change this!
FULL_PATH = os.path.dirname(os.path.abspath(__file__))

#This is the directory for the SP.
WORKING_DIR = FULL_PATH + "/"

#A shared server cache for the IdP. The cache expects a dictionary, but you can use a database by implementing the
#dictionary interface.
CACHE = {}
#The cache as a sqlite database.
#CACHE = Sqllite3Dict(WORKING_DIR + "sp_cache1.sqlite3")

#If the assertion is encrypted for the desination SP you have to copy the complete assertion.
#Set this value to true. This is a special case and the normal value is false!
COPY_ASSERTION = True

#The amount of time in minutes an SP cert will be saved in the cache.
CERT_TIMEOUT = 15

#True if you want to anonymize the assertion form the IdP.
#If COPY_ASSERTION is true this flag is of no use.
ANONYMIZE = False

#This salt is the key to perform a more secure anonymize service.
#YOU SHOULD NEVER USE THE DEFAULT VALUE! Please change this!
ANONYMIZE_SALT = "ddlfjdslk32432FDGFGFDSG5436453rgDRGFDGDFSGQREGAFDG#dgasdgflsdkj45r#"

#This is a map for Open Id connect to Saml2.
#The proxy will give the same response for OAuth2.
OPENID2SAMLMAP = {
    "sub": "uid",
    "name": "displayName",
    "given_name": "givenname",
    "family_name": "sn",
    "middle_name": "",
    "nickname":	"eduPersonNickname",
    "preferred_username": "uid",
    #"profile": "member",
    "profile": "eduPersonScopedAffiliation",
    "picture": "jpegPhoto",
    "website": "labeledURI",
    "email": "email",
    #"email_verified": "Missing
    "gender": "",
    "birthdate": "norEduPersonNIN",
    #zoneinfo timezone
    "locale": "c",
    "phone_number":	"telephoneNumber",
    #phone_number_verified
    "address": "registeredAddress",
    "updated_at": ""  # When information was updated
}


#Traditional pysaml2 configuration for a SP. View more documentation for pysaml2.
CONFIG = {
    "entityid": "%s/%shansidproxy.xml" % (BASE, ""),
    "description": "Test Hans local IdProxy SP",
    "entity_category": [COC, RESEARCH_AND_EDUCATION, HEI, SFS_1993_1153, NREN, EU],
    "service": {
        "sp": {
            "name": "Test Hans local IdProxy SP",
            "authn_requests_signed": "true",
            "want_response_signed": "true",
            "endpoints": {
                "assertion_consumer_service": [
                    (BASE + "/" + ASCREDIRECT, BINDING_HTTP_REDIRECT),
                    (BASE + "/" + ASCPOST, BINDING_HTTP_POST)
                ],
                "required_attributes": ["uid"],
                "discovery_response": [
                    ("%s/%s" % (BASE, DISCOENDPOINT), BINDING_DISCO)
                ],
            }
        },
    },
    "key_file": WORKING_DIR+"sp_cert/localhost.key",
    "cert_file": WORKING_DIR+"sp_cert/localhost.crt",
    "xmlsec_binary": xmlsec_path,
    "metadata": {
        "local": ["/Users/haho0032/Develop/githubFork/pysaml2/example/idp2/idp2.xml"]
        #"remote": [{"url": "http://130.239.201.5/role/idp.xml", "cert": None}],
    },
    "name_form": NAME_FORMAT_URI,
    "organization": {
        "name": "Test Hans local IdProxy SP",
        "display_name": [("Test Hans local IdProxy SP", "en")],
        "url": ISSUER,
    },
    "contact_person": [
        {
            "contact_type": "technical",
            "given_name": "Hans",
            "sur_name": "Hoerberg",
            "email_address": "hans.horberg@umu.se"
        },
    ],
    "logger": {
        "rotating": {
            "filename": "sp.log",
            "maxBytes": 100000,
            "backupCount": 5,
        },
        "loglevel": "debug",
    }
}

#Contains all valid attributes and valid values for that attribute.
VALID_ATTRIBUTE_RESPONSE = {
    #"eduPersonAffiliation": ["student"],
    "eduPersonScopedAffiliation": ["student"]
}

#Contains all attributes that will be returned.
#Only value that contains the values in the value list will be returned. If None will all values be returned.
ATTRIBUTE_WHITELIST = {
    "eduPersonScopedAffiliation": ["student"]
}


