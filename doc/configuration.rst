.. _configuration:

*****************
PEFIM proxy setup
*****************


Server configuration
====================
There are 2 main config files:
pefim_server_conf
  controls
  1. the be havior of the http server (server location, TLS)
  2. the session handling and
  3. NameID mapping from IDP to SP

pefim_server_conf
  This is a pure pysaml2 entity config file to control the SAML behavior of the
  IDP and SP sides of the proxy.

Read the comments in the files **example/pefim_server_conf.example** and **example/pefim_proxy_conf.example**.

Certificate configuration
-------------------------
Key material for TLS endpoints is in SERVER_CERT, SERVER_KEY and CERT_CHAIN.
SAML signatures are processed with the convential pysam2 configuration, e.g. key material for
SAML signatures in is CONFIG['key_file'] and CONFIG['cert_file'], keys for signature validation
are in metadata.

Metadata configuration
----------------------
The metadata location is CONFIG['metadata']. Pysaml2 allows for remote, local and multiple sources.

Grouping SPs: The PEFIM model requires that multple SPs are mapped into a single SP to the IDP. The criterium
to decide which SPs are put into the same group is the identical set of requested attributes. This is achieved
by the assumption that requested attributes are defined by an EntitiyCategory element in the SP's EntityDescriptor.
Thererfore each SP's metadata MUST contain an EntityDescriptor

Configuring a single IDP insgtead of IDP discovery
--------------------------------------------------
If there is a single IDP, use the -e switch when starting the proxy server.

IdP and SP configuration
========================
pysaml2 configuration file for both SP and IdP. View an example in **example/pefim_proxy_conf.example**.
