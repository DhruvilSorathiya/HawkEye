import pytest
import unittest

from modules.hep_bgpview import hep_bgpview
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleBgpview(unittest.TestCase):

    def test_opts(self):
        module = hep_bgpview()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_bgpview()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_bgpview()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_bgpview()
        self.assertIsInstance(module.producedEvents(), list)
