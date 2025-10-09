import pytest
import unittest

from modules.hep_debounce import hep_debounce
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleDebounce(unittest.TestCase):

    def test_opts(self):
        module = hep_debounce()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_debounce()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_debounce()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_debounce()
        self.assertIsInstance(module.producedEvents(), list)
