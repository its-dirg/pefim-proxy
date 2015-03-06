# -*- coding: utf-8 -*-

#Port for the webserver.
PORT=8999
#True if HTTPS should be used, false is equal to HTTP.
HTTPS=True

#Server hostname
HOST="hashog.umdc.umu.se"
#BASEURL="hashog.umdc.umu.se"
if HTTPS:
    BASEURL = "https://%s" % HOST
else:
    BASEURL = "http://%s" % HOST

#Full URL to the OP server
ISSUER = "%s:%s" % (BASEURL, PORT)

IDP_FRONTEND = True

OP_FRONTEND = True

#Filename for log.
LOG_FILE = 'server.log'

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
