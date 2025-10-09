import pytest
import unittest

from modules.hep_callername import hep_callername
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCallername(unittest.TestCase):

    def test_opts(self):
        module = hep_callername()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_callername()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_callername()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_callername()
        self.assertIsInstance(module.producedEvents(), list)
