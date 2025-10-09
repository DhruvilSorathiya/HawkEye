import pytest
import unittest

from modules.hep_ripe import hep_ripe
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleRipe(unittest.TestCase):

    def test_opts(self):
        module = hep_ripe()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_ripe()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_ripe()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_ripe()
        self.assertIsInstance(module.producedEvents(), list)
