import pytest
import unittest

from modules.hep_crxcavator import hep_crxcavator
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCrxcavator(unittest.TestCase):

    def test_opts(self):
        module = hep_crxcavator()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_crxcavator()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_crxcavator()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_crxcavator()
        self.assertIsInstance(module.producedEvents(), list)
