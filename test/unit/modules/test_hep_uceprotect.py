import pytest
import unittest

from modules.hep_uceprotect import hep_uceprotect
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleUceprotect(unittest.TestCase):

    def test_opts(self):
        module = hep_uceprotect()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_uceprotect()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_uceprotect()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_uceprotect()
        self.assertIsInstance(module.producedEvents(), list)
