import pytest
import unittest

from modules.hep_subdomain_takeover import hep_subdomain_takeover
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleSubdomain_takeover(unittest.TestCase):

    def test_opts(self):
        module = hep_subdomain_takeover()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_subdomain_takeover()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_subdomain_takeover()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_subdomain_takeover()
        self.assertIsInstance(module.producedEvents(), list)
