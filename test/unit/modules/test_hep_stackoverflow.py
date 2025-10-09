import pytest
import unittest

from modules.hep_stackoverflow import hep_stackoverflow
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleStackoverflow(unittest.TestCase):

    def test_opts(self):
        module = hep_stackoverflow()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_stackoverflow()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_stackoverflow()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_stackoverflow()
        self.assertIsInstance(module.producedEvents(), list)
