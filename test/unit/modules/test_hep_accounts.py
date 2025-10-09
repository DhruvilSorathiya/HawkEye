import pytest
import unittest

from modules.hep_accounts import hep_accounts
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleAccounts(unittest.TestCase):

    def test_opts(self):
        module = hep_accounts()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_accounts()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_accounts()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_accounts()
        self.assertIsInstance(module.producedEvents(), list)
