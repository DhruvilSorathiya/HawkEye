import pytest
import unittest

from modules.hep_arin import hep_arin
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleArin(unittest.TestCase):

    def test_opts(self):
        module = hep_arin()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_arin()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_arin()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_arin()
        self.assertIsInstance(module.producedEvents(), list)
