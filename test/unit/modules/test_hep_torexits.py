import pytest
import unittest

from modules.hep_torexits import hep_torexits
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleTorexits(unittest.TestCase):

    def test_opts(self):
        module = hep_torexits()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_torexits()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_torexits()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_torexits()
        self.assertIsInstance(module.producedEvents(), list)
