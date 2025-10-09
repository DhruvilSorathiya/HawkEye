import pytest
import unittest

from modules.hep_opennic import hep_opennic
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleOpenNic(unittest.TestCase):

    def test_opts(self):
        module = hep_opennic()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_opennic()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_opennic()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_opennic()
        self.assertIsInstance(module.producedEvents(), list)
