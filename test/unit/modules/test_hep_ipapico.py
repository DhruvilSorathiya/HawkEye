import pytest
import unittest

from modules.hep_ipapico import hep_ipapico
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleipApico(unittest.TestCase):

    def test_opts(self):
        module = hep_ipapico()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)

        module = hep_ipapico()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_ipapico()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_ipapico()
        self.assertIsInstance(module.producedEvents(), list)
