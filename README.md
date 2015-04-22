# pefim_proxy

The pefim-proxy project aims at building a SAML to SAML proxy to support the `PEFIM`_ profile.

.. _PEFIM: https://kantarainitiative.org/confluence/display/fiwg/PEFIM+SAML+profile

The proxy will in the default setting act transparent in sense of entity categories and name id format.

If the calling sp is configured to use persistent name id format and uses the entity category PVP2, then will the proxy
call the underlying IdP with the same configuration. Note that the supported entity categories must be added to the
configuration.

*******************
Quick install guide
*******************

Install PEFIM proxy using docker
================================

Download the PEFIM docker project from: https://github.com/its-dirg/pefim-proxy_docker

For more instructions read the documentation inclued in the docker project.


Install PEFIM proxy
===================

Download the PEFIM docker project from: https://github.com/its-dirg/pefim-proxy

The PEFIM proxy includes an example configuration in the folder **example*** that can be used to get your proxy up and running quick.

The only configuration in the example that must be changed is the metadata and/or discovery server.

Copy the file **example/pefim_proxy_conf.example** to **example/pefim_proxy_conf.py**/

Copy the file **example/pefim_server_conf.example** to **example/pefim_server_conf.py**/

In the file **example/pefim_proxy_conf.py**/ change "metadata" in the CONFIG dictionary to your metadata settings,
using pysaml2 syntax.

In the file **example/pefim_proxy_conf.py**/ change DISCO_SRV to the discovery server you are using. This is not
necessary if your are only going to use one underlying IdP.


To start the proxy for one IdP run::

    pefim_server pefim_proxy_conf pefim_server_conf -e IdPEntityId

To start the proxy with discovery server::

    pefim_server pefim_proxy_conf pefim_server_conf
