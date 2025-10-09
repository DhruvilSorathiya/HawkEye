import pytest
import unittest

from modules.hep_dnsbrute import hep_dnsbrute
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleDnsBrute(unittest.TestCase):

    def test_opts(self):
        module = hep_dnsbrute()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_dnsbrute()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_dnsbrute()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_dnsbrute()
        self.assertIsInstance(module.producedEvents(), list)
