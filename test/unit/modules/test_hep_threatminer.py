import pytest
import unittest

from modules.hep_threatminer import hep_threatminer
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleThreatminer(unittest.TestCase):

    def test_opts(self):
        module = hep_threatminer()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_threatminer()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_threatminer()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_threatminer()
        self.assertIsInstance(module.producedEvents(), list)
