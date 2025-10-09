import pytest
import unittest

from modules.hep_maltiverse import hep_maltiverse
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleMaltiverse(unittest.TestCase):

    def test_opts(self):
        module = hep_maltiverse()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_maltiverse()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_maltiverse()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_maltiverse()
        self.assertIsInstance(module.producedEvents(), list)
