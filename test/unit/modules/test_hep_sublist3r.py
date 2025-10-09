import pytest
import unittest

from modules.hep_sublist3r import hep_sublist3r
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleSublist3r(unittest.TestCase):

    def test_opts(self):
        module = hep_sublist3r()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_sublist3r()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_sublist3r()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_sublist3r()
        self.assertIsInstance(module.producedEvents(), list)
