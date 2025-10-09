import pytest
import unittest

from modules.hep_tldsearch import hep_tldsearch
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleTldsearch(unittest.TestCase):

    def test_opts(self):
        module = hep_tldsearch()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)

        module = hep_tldsearch()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_tldsearch()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_tldsearch()
        self.assertIsInstance(module.producedEvents(), list)
