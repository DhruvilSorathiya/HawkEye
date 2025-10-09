import pytest
import unittest

from modules.hep_robtex import hep_robtex
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleRobtex(unittest.TestCase):

    def test_opts(self):
        module = hep_robtex()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_robtex()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_robtex()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_robtex()
        self.assertIsInstance(module.producedEvents(), list)
