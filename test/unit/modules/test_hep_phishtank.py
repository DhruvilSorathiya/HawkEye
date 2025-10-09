import pytest
import unittest

from modules.hep_phishtank import hep_phishtank
from helib import HawkEye


@pytest.mark.usefixtures
class TestModulePhishtank(unittest.TestCase):

    def test_opts(self):
        module = hep_phishtank()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_phishtank()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_phishtank()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_phishtank()
        self.assertIsInstance(module.producedEvents(), list)
