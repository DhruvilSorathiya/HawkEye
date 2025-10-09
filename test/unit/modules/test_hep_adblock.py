import pytest
import unittest

from modules.hep_adblock import hep_adblock
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleAdblock(unittest.TestCase):

    def test_opts(self):
        module = hep_adblock()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_adblock()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_adblock()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_adblock()
        self.assertIsInstance(module.producedEvents(), list)
