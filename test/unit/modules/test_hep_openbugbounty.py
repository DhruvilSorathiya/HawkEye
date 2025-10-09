import pytest
import unittest

from modules.hep_openbugbounty import hep_openbugbounty
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleOpenbugbounty(unittest.TestCase):

    def test_opts(self):
        module = hep_openbugbounty()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_openbugbounty()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_openbugbounty()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_openbugbounty()
        self.assertIsInstance(module.producedEvents(), list)
