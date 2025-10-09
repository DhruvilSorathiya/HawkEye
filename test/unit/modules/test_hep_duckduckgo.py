import pytest
import unittest

from modules.hep_duckduckgo import hep_duckduckgo
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleDuckduckgo(unittest.TestCase):

    def test_opts(self):
        module = hep_duckduckgo()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_duckduckgo()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_duckduckgo()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_duckduckgo()
        self.assertIsInstance(module.producedEvents(), list)
