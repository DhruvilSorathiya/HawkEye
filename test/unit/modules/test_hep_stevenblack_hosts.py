import pytest
import unittest

from modules.hep_stevenblack_hosts import hep_stevenblack_hosts
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleStevenblackHosts(unittest.TestCase):

    def test_opts(self):
        module = hep_stevenblack_hosts()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_stevenblack_hosts()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_stevenblack_hosts()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_stevenblack_hosts()
        self.assertIsInstance(module.producedEvents(), list)
