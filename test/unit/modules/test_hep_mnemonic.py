import pytest
import unittest

from modules.hep_mnemonic import hep_mnemonic
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleMnemonic(unittest.TestCase):

    def test_opts(self):
        module = hep_mnemonic()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_mnemonic()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_mnemonic()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_mnemonic()
        self.assertIsInstance(module.producedEvents(), list)
