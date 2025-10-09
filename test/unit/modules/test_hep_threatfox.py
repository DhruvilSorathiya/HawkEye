import pytest
import unittest

from modules.hep_threatfox import hep_threatfox
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleThreatFox(unittest.TestCase):

    def test_opts(self):
        module = hep_threatfox()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_threatfox()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_threatfox()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_threatfox()
        self.assertIsInstance(module.producedEvents(), list)
