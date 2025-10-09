import pytest
import unittest

from modules.hep_hosting import hep_hosting
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleHosting(unittest.TestCase):

    def test_opts(self):
        module = hep_hosting()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_hosting()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_hosting()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_hosting()
        self.assertIsInstance(module.producedEvents(), list)
