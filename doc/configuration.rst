.. _configuration:

*****************
PEFIM proxy setup
*****************


Server configuration
====================
There are 2 main config files:
pefim_server_conf
-----------------
  controls
  1. the be havior of the http server (server location, TLS)
  2. the session handling and
  3. NameID mapping from IDP to SP

Certificate configuration
^^^^^^^^^^^^^^^^^^^^^^^^^
Key material for TLS endpoints is in SERVER_CERT, SERVER_KEY and CERT_CHAIN.
SAML signatures are processed with the convential pysam2 configuration, e.g. key material for
SAML signatures in is CONFIG['key_file'] and CONFIG['cert_file'], keys for signature validation
are in metadata.


pefim_proxy_conf
----------------
  This is a pure pysaml2 entity config file to control the SAML behavior of the
  IDP and SP sides of the proxy.

Read the comments in the files **example/pefim_server_conf.example** and **example/pefim_proxy_conf.example**.

Metadata configuration
^^^^^^^^^^^^^^^^^^^^^^
The metadata location is CONFIG['metadata']. Pysaml2 allows for remote, local and multiple sources.

Grouping SPs: The PEFIM model requires that multple SPs are mapped into a single SP to the IDP. The criterium
to decide which SPs are put into the same group is the identical set of requested attributes. This is achieved
by the assumption that requested attributes are defined by an EntitiyCategory element in the SP's EntityDescriptor.
Thererfore each SP's metadata MUST contain an EntityDescriptor

Extra configuration
^^^^^^^^^^^^^^^^^^^
pefim_proxy_conf can be extended with the following configurations.

#Force the NameID to be persistent regardless of <NameIDFormat> values in the SP metadata.
#If set to True, the nameid will always be persistent, i.e. the nameid value will always
#be the same per SP, by hashing or encrypting the IDP's NameID.
FORCE_PRESISTENT_NAMEID = True

#If an hash algorithm is used instead of encryption (via the startup option) a dictionary can be used to store the
#mapping for reverse lookups.
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

Configuring a single IDP instead of IDP discovery
-------------------------------------------------
If there is a single IDP, use the -e switch when starting the proxy server.

*****************************
PEFIM proxy command line args
*****************************

Synopsis:  pefim_server proxy_conf server_conf [options]

proxy_config	Configuration file for the pysaml sp and idp.
server_config	Configuration file with server settings.

-d	 			debug  (Not implemented yet)
-pe				Add this flag to print the exception that is the reason for an invalid configuration error.
-e				Entity id for the underlying IdP if only one IdP should be used. Otherwise will a discovery server be used.
-e_alg			Encryption algorithm to be used for target id 2.
				Approved values: aes_128_cbc, aes_128_cfb, aes_128_ecb, aes_192_cbc, aes_192_cfb,
				aes_192_ecb, aes_256_cbc, aes_256_cfb and aes_256_ecb.
				Default is aes_128_cbc if flag is left out.
-key			Encryption key to be used for target id2. Approved values is a valid key for the
				chosen encryption algorithm in e_alg.
-h_alg			Hash algorithm to be used for target id 2 and the proxy userid. Approved values:
				md5, sha1, sha224, sha256, sha384, sha512. Default is sha256 if flag is left out.
-iv				Initialization vector to be used for the encryption. Default is to create a random value
				for each call if the encrypted messages can be saved, otherwise will the same
				random value be used for each call. If the same iv is to be used each call its
				recommended to assign a value to make sure the same iv is used if the server restart.


Example:
--------
make_proxy_metadata pefim_proxy_conf > pefim_proxy_conf.xml
pefim_server pefim_proxy_conf pefim_server_conf -e https://localhost:8088/TestPEFIMIdP.xml