import unittest
from argparse import Namespace
from pefimproxy.server import WsgiApplication


class ServerConfigurationTestCase(unittest.TestCase):
    def setup_class(self):
        pass

    def test_server_config_files_ok(self):
        valid, message = WsgiApplication.validate_server_config(
            Namespace(
                server_config="pefim_server_conf_default"
            )
        )
        assert valid, "Missing the configuration file pefim_server_conf_default.py"

    def test_server_config_missing_file(self):
        valid, message = WsgiApplication.validate_server_config(
            Namespace(
                server_config="pefim_server_conf_missing"
            )
        )
        assert valid is False, "The file pefim_server_conf_missing.py must not exists!"

    def test_server_config_missing_parameters(self):
        valid, message = WsgiApplication.validate_server_config(
            Namespace(
                server_config="empty"
            )
        )
        assert valid is False, "No parameter should exist."
        for param in WsgiApplication.SERVER_CONF_MANDITORY_PARAMETERS:
            assert param in message, "The parameter %s should be in the message." % param

    def test_config_files_ok(self):
        valid, message = WsgiApplication.validate_config(
            Namespace(
                config="pefim_proxy_conf_local"
            )
        )
        assert valid, "Missing the configuration file pefim_proxy_conf_local.py"

    def test_config_missing_file(self):
        valid, message = WsgiApplication.validate_config(
            Namespace(
                config="pefim_proxy_conf_missing"
            )
        )
        assert valid is False, "The file pefim_proxy_conf_missing.py must not exists!"

    def test_missing_parameters(self):
        valid, message = WsgiApplication.validate_config(
            Namespace(
                config="empty"
            )
        )
        assert valid is False, "No parameter should exist."
        for param in WsgiApplication.CONF_MANDITORY_PARAMETERS:
            assert param in message, "The parameter %s should be in the message." % param