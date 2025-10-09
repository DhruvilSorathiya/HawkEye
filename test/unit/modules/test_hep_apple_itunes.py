import pytest
import unittest

from modules.hep_apple_itunes import hep_apple_itunes
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleAppleItunes(unittest.TestCase):

    def test_opts(self):
        module = hep_apple_itunes()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_apple_itunes()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_apple_itunes()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_apple_itunes()
        self.assertIsInstance(module.producedEvents(), list)
