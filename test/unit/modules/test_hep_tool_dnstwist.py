import pytest
import unittest

from modules.hep_tool_dnstwist import hep_tool_dnstwist
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleToolDnstwist(unittest.TestCase):

    def test_opts(self):
        module = hep_tool_dnstwist()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_tool_dnstwist()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_tool_dnstwist()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_tool_dnstwist()
        self.assertIsInstance(module.producedEvents(), list)
