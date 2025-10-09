import pytest
import unittest

from modules.hep_commoncrawl import hep_commoncrawl
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCommoncrawl(unittest.TestCase):

    def test_opts(self):
        module = hep_commoncrawl()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_commoncrawl()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_commoncrawl()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_commoncrawl()
        self.assertIsInstance(module.producedEvents(), list)
