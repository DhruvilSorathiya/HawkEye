import pytest
import unittest

from modules.hep_cinsscore import hep_cinsscore
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCinsscore(unittest.TestCase):

    def test_opts(self):
        module = hep_cinsscore()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_cinsscore()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_cinsscore()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_cinsscore()
        self.assertIsInstance(module.producedEvents(), list)
