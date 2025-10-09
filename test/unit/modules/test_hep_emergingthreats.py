import pytest
import unittest

from modules.hep_emergingthreats import hep_emergingthreats
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleEmergingthreats(unittest.TestCase):

    def test_opts(self):
        module = hep_emergingthreats()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_emergingthreats()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_emergingthreats()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_emergingthreats()
        self.assertIsInstance(module.producedEvents(), list)
