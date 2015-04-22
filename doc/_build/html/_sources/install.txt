.. _install:

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


