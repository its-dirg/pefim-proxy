# coding=utf-8
from setuptools import setup

setup(
    name="pefimproxy",
    version="0.1",
    description='SAML proxy for the pefim profile.',
    author="Hans Hörberg",
    author_email="hans.horberg@umu.se",
    license="Apache 2.0",
    packages=["pefimproxy", "pefimproxy/util"],
    package_dir={"": "src"},
    classifiers=["Development Status :: 0.1 - Beta",
                 "License :: OSI Approved :: Apache Software License",
                 "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires=["cherrypy==3.2.4"],
    entry_points={
        'console_scripts': ['make_proxy_metadata=pefimproxy.util.make_proxy_metadata:main',
                            'pefim_server=pefimproxy.pefim_server:main'],
    },
    zip_safe=False,
    data_files=[
        ("/opt/pefimproxy/static/", [
            "static/robots.txt"
        ]),
    ]
)
