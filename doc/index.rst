.. pefim_proxy documentation master file, created by
   sphinx-quickstart on Wed Apr 22 14:18:43 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to pefim-proxy's documentation!
=======================================

The pefim-proxy project aims at building a SAML to SAML proxy to support the `PEFIM`_ profile.

.. _PEFIM: https://kantarainitiative.org/confluence/display/fiwg/PEFIM+SAML+profile

The proxy will in the default setting act transparent in sense of entity categories and name id format.

If the calling sp is configured to use persistent name id format and uses the entity category PVP2, then will the proxy
call the underlying IdP with the same configuration. Note that the supported entity categories must be added to the
configuration.

.. toctree::
   :maxdepth: 3

   install
   run
   configuration

.. toctree::
    :maxdepth: 1

..    pefimproxy


.. raw:: html

    <a href="https://github.com/its-dirg/pefim-proxy" class="github" target="_blank">
        <img style="position: absolute; top: 0; right: 0; border: 0;" src="_static/ViewmeonGitHub.png" alt="View me on GitHub"  class="github"/>
    </a>