import pytest
import unittest

from modules.hep_cleanbrowsing import hep_cleanbrowsing
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCleanbrowsing(unittest.TestCase):

    def test_opts(self):
        module = hep_cleanbrowsing()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_cleanbrowsing()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_cleanbrowsing()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_cleanbrowsing()
        self.assertIsInstance(module.producedEvents(), list)
