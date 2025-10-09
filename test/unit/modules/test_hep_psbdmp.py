import pytest
import unittest

from modules.hep_psbdmp import hep_psbdmp
from helib import HawkEye


@pytest.mark.usefixtures
class TestModulePsbdmp(unittest.TestCase):

    def test_opts(self):
        module = hep_psbdmp()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_psbdmp()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_psbdmp()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_psbdmp()
        self.assertIsInstance(module.producedEvents(), list)
