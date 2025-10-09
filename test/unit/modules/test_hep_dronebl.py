import pytest
import unittest

from modules.hep_dronebl import hep_dronebl
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleDronebl(unittest.TestCase):

    def test_opts(self):
        module = hep_dronebl()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_dronebl()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_dronebl()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_dronebl()
        self.assertIsInstance(module.producedEvents(), list)
