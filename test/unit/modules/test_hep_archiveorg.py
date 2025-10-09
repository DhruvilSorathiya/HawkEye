import pytest
import unittest

from modules.hep_archiveorg import hep_archiveorg
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleArchiveorg(unittest.TestCase):

    def test_opts(self):
        module = hep_archiveorg()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_archiveorg()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_archiveorg()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_archiveorg()
        self.assertIsInstance(module.producedEvents(), list)
