import pytest
import unittest

from modules.hep_ahmia import hep_ahmia
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleAhmia(unittest.TestCase):

    def test_opts(self):
        module = hep_ahmia()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)

        module = hep_ahmia()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_ahmia()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_ahmia()
        self.assertIsInstance(module.producedEvents(), list)
