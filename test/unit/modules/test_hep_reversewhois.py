import pytest
import unittest

from modules.hep_reversewhois import hep_reversewhois
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleReversewhois(unittest.TestCase):

    def test_opts(self):
        module = hep_reversewhois()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_reversewhois()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_reversewhois()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_reversewhois()
        self.assertIsInstance(module.producedEvents(), list)
