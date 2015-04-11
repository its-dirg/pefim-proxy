# -*- coding: utf-8 -*-

#Port for the webserver.
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

#Filename for log.
LOG_FILE = 'pefim_server.log'

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

#Database with the underlying IDP's name_id as key and the proxy generated name_id as value.
NAME_ID_ORG_NEW = {}
#Database with the underlying IDP's name_id as value and the proxy generated name_id as key.
NAME_ID_NEW_ORG = {}