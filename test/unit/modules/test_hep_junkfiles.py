import pytest
import unittest

from modules.hep_junkfiles import hep_junkfiles
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleJunkfiles(unittest.TestCase):

    def test_opts(self):
        module = hep_junkfiles()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_junkfiles()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_junkfiles()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_junkfiles()
        self.assertIsInstance(module.producedEvents(), list)
