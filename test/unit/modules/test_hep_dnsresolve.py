import pytest
import unittest

from modules.hep_dnsresolve import hep_dnsresolve
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleDnsResolve(unittest.TestCase):

    def test_opts(self):
        module = hep_dnsresolve()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_dnsresolve()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_dnsresolve()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_dnsresolve()
        self.assertIsInstance(module.producedEvents(), list)
