import pytest
import unittest

from modules.hep_similar import hep_similar
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleSimilar(unittest.TestCase):

    def test_opts(self):
        module = hep_similar()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_similar()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_similar()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_similar()
        self.assertIsInstance(module.producedEvents(), list)
