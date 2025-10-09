import pytest
import unittest

from modules.hep_crossref import hep_crossref
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCrossref(unittest.TestCase):

    def test_opts(self):
        module = hep_crossref()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_crossref()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_crossref()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_crossref()
        self.assertIsInstance(module.producedEvents(), list)
