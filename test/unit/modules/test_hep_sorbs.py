import pytest
import unittest

from modules.hep_sorbs import hep_sorbs
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleSorbs(unittest.TestCase):

    def test_opts(self):
        module = hep_sorbs()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_sorbs()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_sorbs()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_sorbs()
        self.assertIsInstance(module.producedEvents(), list)
