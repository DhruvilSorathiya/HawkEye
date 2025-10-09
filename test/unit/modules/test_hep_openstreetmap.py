import pytest
import unittest

from modules.hep_openstreetmap import hep_openstreetmap
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleopenstreetmap(unittest.TestCase):

    def test_opts(self):
        module = hep_openstreetmap()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_openstreetmap()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_openstreetmap()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_openstreetmap()
        self.assertIsInstance(module.producedEvents(), list)
