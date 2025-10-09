import pytest
import unittest

from modules.hep_comodo import hep_comodo
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleComodo(unittest.TestCase):

    def test_opts(self):
        module = hep_comodo()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_comodo()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_comodo()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_comodo()
        self.assertIsInstance(module.producedEvents(), list)
