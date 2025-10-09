import pytest
import unittest

from modules.hep_google_tag_manager import hep_google_tag_manager
from helib import HawkEye


@pytest.mark.usefixtures
class TestModulesGoogleTagManager(unittest.TestCase):

    def test_opts(self):
        module = hep_google_tag_manager()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_google_tag_manager()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_google_tag_manager()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_google_tag_manager()
        self.assertIsInstance(module.producedEvents(), list)
