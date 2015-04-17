# -*- coding: utf-8 -*-

#Port for the webserver.
import os

PORT = 8999
#True if HTTPS should be used, false is equal to HTTP.
HTTPS = True

#Server hostname
HOST = "localhost"

if HTTPS:
    BASEURL = "https://%s" % HOST
else:
    BASEURL = "http://%s" % HOST

#Full URL to the OP server
ISSUER = "%s:%s" % (BASEURL, PORT)

BASEDIR = os.path.abspath(os.path.dirname(__file__))

#Filename for log.
LOG_FILE = 'tests/pefim_server.log'

#If HTTPS is true you have to assign the server cert, key and certificate chain.
SERVER_CERT = "httpsCert/localhost.crt"
SERVER_KEY = "httpsCert/localhost.key"
#CERT_CHAIN="certs/chain.pem"
CERT_CHAIN = None

#Beaker session configuration.
#This session can be configured to use database, file, or memory.
SESSION_OPTS = {
    'session.type': 'memory',
    'session.cookie_expires': True, #Expire when the session is closed.
    #'session.data_dir': './data',
    'session.auto': True,
    #'session.timeout' : 900 #Never expires only when the session is closed.
}

#If value is not existing or False name will answer according to the metadata from the SP.
#If set to True, the nameid will always be persistant.
#No matter what setting, the nameid value will always be the same. That is based on the underlying idp as
#a hash or encrypted.
FORCE_PRESISTANT_NAMEID = True

#If value is not existing or False will all nameid values(tid2) generated from an underlying IdP with the same nameid
# be cached in the proxy and the same nameid(tid2) will always be returned.
#If set to True, a new nameid(tid2) value will be generated everytime.
FORCE_NO_USERID_SUBJECT_CACHEING = True

#Database/dictionary with the underlying IDP's nameid(tid1) as key and the proxy generated nameid(tid2) as value.
#If None or removed will no values be saved.
TID1_TO_TID2 = None #{}
#Database/dictionary with the underlying IDP's nameid(tid1) as value and the proxy generated nameid(tid2) as key.
#If None or removed will no valus be saved.
TID2_TO_TID1 = None #{}
#Database/dictionary containing the encrypted tid2 value as key and initialization vector(iv) as value. If a
#database/dictionary exists a new vi will be generated for each encryption performed.
#If None or removed will no valus be saved and the same iv be used for each encryption.
ENCMSG_TO_IV = None #{}
