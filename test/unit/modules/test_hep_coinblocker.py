import pytest
import unittest

from modules.hep_coinblocker import hep_coinblocker
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCoinblocker(unittest.TestCase):

    def test_opts(self):
        module = hep_coinblocker()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_coinblocker()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_coinblocker()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_coinblocker()
        self.assertIsInstance(module.producedEvents(), list)
