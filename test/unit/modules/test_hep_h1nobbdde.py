import pytest
import unittest

from modules.hep_h1nobbdde import hep_h1nobbdde
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleH1nobbdde(unittest.TestCase):

    def test_opts(self):
        module = hep_h1nobbdde()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_h1nobbdde()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_h1nobbdde()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_h1nobbdde()
        self.assertIsInstance(module.producedEvents(), list)
