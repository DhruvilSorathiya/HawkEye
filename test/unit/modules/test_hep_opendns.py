import pytest
import unittest

from modules.hep_opendns import hep_opendns
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleOpendns(unittest.TestCase):

    def test_opts(self):
        module = hep_opendns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_opendns()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_opendns()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_opendns()
        self.assertIsInstance(module.producedEvents(), list)
