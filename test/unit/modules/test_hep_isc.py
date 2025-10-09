import pytest
import unittest

from modules.hep_isc import hep_isc
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleisc(unittest.TestCase):

    def test_opts(self):
        module = hep_isc()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_isc()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_isc()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_isc()
        self.assertIsInstance(module.producedEvents(), list)
