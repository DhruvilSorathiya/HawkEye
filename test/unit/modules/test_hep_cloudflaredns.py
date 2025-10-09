import pytest
import unittest

from modules.hep_cloudflaredns import hep_cloudflaredns
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCloudflaredns(unittest.TestCase):

    def test_opts(self):
        module = hep_cloudflaredns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_cloudflaredns()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_cloudflaredns()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_cloudflaredns()
        self.assertIsInstance(module.producedEvents(), list)
