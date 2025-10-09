import pytest
import unittest

from modules.hep_portscan_tcp import hep_portscan_tcp
from helib import HawkEye


@pytest.mark.usefixtures
class TestModulePortscanTcp(unittest.TestCase):

    def test_opts(self):
        module = hep_portscan_tcp()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_portscan_tcp()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_portscan_tcp()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_portscan_tcp()
        self.assertIsInstance(module.producedEvents(), list)
