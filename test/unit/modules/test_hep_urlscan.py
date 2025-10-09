import pytest
import unittest

from modules.hep_urlscan import hep_urlscan
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleUrlscan(unittest.TestCase):

    def test_opts(self):
        module = hep_urlscan()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_urlscan()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_urlscan()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_urlscan()
        self.assertIsInstance(module.producedEvents(), list)
