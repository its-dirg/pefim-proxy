#!/usr/bin/env python

__author__ = 'haho0032'


def main():
    import argparse
    import os, sys
    from saml2.config import config_factory, Config
    from saml2.metadata import create_metadata_string, entity_descriptor, entities_descriptor
    from saml2.sigver import make_temp, security_context
    from saml2.validate import valid_instance
    from pefimproxy.util.config import get_configurations

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='valid', default="4",
                        help="How long, in days, the metadata is valid from the time of creation")
    parser.add_argument('-c', dest='cert', help='certificate')
    parser.add_argument('-i', dest='id',
                        help="The ID of the entities descriptor in the metadata")
    parser.add_argument('-k', dest='keyfile',
                        help="A file with a key to sign the metadata with")
    parser.add_argument('-n', dest='name')
    parser.add_argument('-s', dest='sign', action='store_true',
                        help="sign the metadata")
    parser.add_argument('-x', dest='xmlsec',
                    help="xmlsec binaries to be used for the signing")
    parser.add_argument(dest="config")

    ed_id = "pefim_proxy"
    valid_for = 0
    nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
    paths = [".", "/opt/local/bin"]
    args = parser.parse_args()

    if args.valid:
        # translate into hours
        valid_for = int(args.valid) * 24

    sys.path.insert(0, os.getcwd())
    idp_conf, sp_confs = get_configurations(args.config)

    eds = []
    if valid_for:
        idp_conf.valid_for = valid_for

    eds.append(entity_descriptor(idp_conf))

    for key in sp_confs:
        cnf = sp_confs[key]["config"]
        if valid_for:
            cnf.valid_for = valid_for
        eds.append(entity_descriptor(cnf))

    conf = Config()
    conf.key_file = args.keyfile
    conf.cert_file = args.cert
    conf.debug = 1
    conf.xmlsec_binary = args.xmlsec
    secc = security_context(conf)

    if args.id:
        ed_id = args.id

    desc, xmldoc = entities_descriptor(eds, valid_for, args.name, ed_id, args.sign, secc)
    valid_instance(desc)
    print desc.to_string(nspair)

if __name__ == '__main__':
    main()
