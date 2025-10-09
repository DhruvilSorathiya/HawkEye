import pytest
import unittest

from modules.hep_searchcode import hep_searchcode
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCodesearch(unittest.TestCase):

    def test_opts(self):
        module = hep_searchcode()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_searchcode()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_searchcode()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_searchcode()
        self.assertIsInstance(module.producedEvents(), list)
