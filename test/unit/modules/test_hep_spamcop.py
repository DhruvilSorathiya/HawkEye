import pytest
import unittest

from modules.hep_spamcop import hep_spamcop
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleSpamcop(unittest.TestCase):

    def test_opts(self):
        module = hep_spamcop()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_spamcop()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_spamcop()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_spamcop()
        self.assertIsInstance(module.producedEvents(), list)
