.. _scripts:

************
Script guide
************

Guide to generate metadata
==========================

You must create a configuration file for the pysaml2 based service providers(backend) and identity provider(frontend).

To get started you can copy **example/pefim_proxy_conf.example** to a new file like **example/pefim_proxy_conf.py**/.

The proxy configuration is based on a server configuration and to get started with that file copy **example/pefim_server_conf.example** to a new file like **example/pefim_server_conf.py**/.

When all configuration is performed, you will need to generate metadata for the proxy. This can be performed with the
script make_proxy_metadata.

Example::

    make_proxy_metadata pefim_proxy_conf > pefim_proxy_conf.xml


Guide to start the server
=========================

The server depends on the two configuration files, pefim_proxy_conf.py and pefim_server_conf.py, mentioned in the previous header "Guide to generate metadata";

The proxy server is started with the script make_proxy_metadata.

To start the proxy for one IdP run::

    pefim_server pefim_proxy_conf pefim_server_conf -e IdPEntityId

To start the proxy with discovery server::

    pefim_server pefim_proxy_conf pefim_server_conf


For more information about running the pefim proxy run::

    pefim_server -help
    usage: pefim_server [-h] [-d] [-e ENTITYID] [-e_alg E_ALG] [-key KEY]
                        [-h_alg H_ALG] [-iv IV]
                        config server_config

    positional arguments:
      config
      server_config

    optional arguments:
      -h, --help     show this help message and exit
      -d             Not implemented yet.
      -e ENTITYID    Entity id for the underlying IdP if only one IdP should
                     be used. Otherwise will a discovery server be used.
      -e_alg E_ALG   Encryption algorithm to be used for target id 2. Approved
                     values: aes_128_cbc, aes_128_cfb, aes_128_ecb, aes_192_cbc,
                     aes_192_cfb, aes_192_ecb, aes_256_cbc, aes_256_cfb and
                     aes_256_ecbDefault is aes_128_cbc if flag is left out.
      -key KEY       Encryption key to be used for target id2.Approved values is a
                     valid key for the chosen encryption algorithm in e_alg.
      -h_alg H_ALG   Hash algorithm to be used for target id 2 and the proxy
                     userid. Approved values: md5, sha1, sha224, sha256, sha384,
                     sha512 Default is sha256 if flag is left out.
      -iv IV         Initialization vector to be used for the encryption. Default
                     is to create a random value for each call if the encrypted
                     messages can be saved, otherwise will the same random value
                     be used for each call. If the same iv is to be used each call
                     its recommended to assign a value to make sure the same iv is
                     used if the server restart.

