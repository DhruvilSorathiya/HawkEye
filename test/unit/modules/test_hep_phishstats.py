import pytest
import unittest

from modules.hep_phishstats import hep_phishstats
from helib import HawkEye


@pytest.mark.usefixtures
class TestModulePhishstats(unittest.TestCase):

    def test_opts(self):
        module = hep_phishstats()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_phishstats()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_phishstats()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_phishstats()
        self.assertIsInstance(module.producedEvents(), list)
