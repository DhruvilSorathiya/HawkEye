import pytest
import unittest

from modules.hep_wikileaks import hep_wikileaks
from helib import HawkEye


@pytest.mark.usefixtures
class TestModulewikileaks(unittest.TestCase):

    def test_opts(self):
        module = hep_wikileaks()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_wikileaks()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_wikileaks()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_wikileaks()
        self.assertIsInstance(module.producedEvents(), list)
