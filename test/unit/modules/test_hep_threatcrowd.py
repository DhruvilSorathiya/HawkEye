import pytest
import unittest

from modules.hep_threatcrowd import hep_threatcrowd
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleThreatcrowd(unittest.TestCase):

    def test_opts(self):
        module = hep_threatcrowd()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_threatcrowd()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_threatcrowd()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_threatcrowd()
        self.assertIsInstance(module.producedEvents(), list)
