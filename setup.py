# coding=utf-8
from setuptools import setup

setup(
    name="pefim-proxy",
    version="0.1",
    description='SAML proxy for the pefim profile.',
    author = "Hans Hörberg",
    author_email = "hans.horberg@umu.se",
    license="Apache 2.0",
    packages=["pefim-proxy", "pefim-proxy/client", "pefim-proxy/client/sp",
              "pefim-proxy/provider", "pefim-proxy/provider/idp", "pefim-proxy/provider/idp/auth",
              "pefim-proxy/provider/op", "pefim-proxy/util"],
    package_dir = {"": "src"},
    classifiers = ["Development Status :: 0.1 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires = ['oic', 'requests', "pycrypto",
                        "cherrypy==3.2.4", "mako", "pyjwkest", "beaker", "argparse"],

    zip_safe=False,
)
