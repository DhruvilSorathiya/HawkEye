import pytest
import unittest

from modules.hep_alienvaultiprep import hep_alienvaultiprep
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleAlienvaultiprep(unittest.TestCase):

    def test_opts(self):
        module = hep_alienvaultiprep()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_alienvaultiprep()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_alienvaultiprep()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_alienvaultiprep()
        self.assertIsInstance(module.producedEvents(), list)
