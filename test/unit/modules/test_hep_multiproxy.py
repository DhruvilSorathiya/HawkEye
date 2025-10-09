import pytest
import unittest

from modules.hep_multiproxy import hep_multiproxy
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleMultiproxy(unittest.TestCase):

    def test_opts(self):
        module = hep_multiproxy()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_multiproxy()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_multiproxy()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_multiproxy()
        self.assertIsInstance(module.producedEvents(), list)
