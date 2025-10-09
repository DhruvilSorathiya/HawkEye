import pytest
import unittest

from modules.hep_keybase import hep_keybase
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleKeybase(unittest.TestCase):

    def test_opts(self):
        module = hep_keybase()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_keybase()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_keybase()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_keybase()
        self.assertIsInstance(module.producedEvents(), list)
