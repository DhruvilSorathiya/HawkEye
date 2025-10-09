import pytest
import unittest

from modules.hep_opencorporates import hep_opencorporates
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleOpencorporates(unittest.TestCase):

    def test_opts(self):
        module = hep_opencorporates()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_opencorporates()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_opencorporates()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_opencorporates()
        self.assertIsInstance(module.producedEvents(), list)
