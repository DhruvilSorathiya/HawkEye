import pytest
import unittest

from modules.hep_googleobjectstorage import hep_googleobjectstorage
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleGoogleobjectstorage(unittest.TestCase):

    def test_opts(self):
        module = hep_googleobjectstorage()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_googleobjectstorage()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_googleobjectstorage()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_googleobjectstorage()
        self.assertIsInstance(module.producedEvents(), list)
