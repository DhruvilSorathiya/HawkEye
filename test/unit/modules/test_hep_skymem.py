import pytest
import unittest

from modules.hep_skymem import hep_skymem
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleSkymem(unittest.TestCase):

    def test_opts(self):
        module = hep_skymem()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_skymem()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_skymem()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_skymem()
        self.assertIsInstance(module.producedEvents(), list)
