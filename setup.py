# coding=utf-8
from setuptools import setup

setup(
    name="pefimproxy",
    version="0.1",
    description='SAML proxy for the pefim profile.',
    author = "Hans Hörberg",
    author_email = "hans.horberg@umu.se",
    license="Apache 2.0",
    packages=["pefimproxy", "pefimproxy/client", "pefimproxy/client/sp",
              "pefimproxy/provider", "pefimproxy/provider/idp", "pefimproxy/provider/idp/auth",
              "pefimproxy/util"],
    package_dir = {"": "src"},
    classifiers = ["Development Status :: 0.1 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires = ['oic', 'requests', "pycrypto",
                        "cherrypy==3.2.4", "mako", "pyjwkest", "beaker", "argparse"],

    zip_safe=False,
)
