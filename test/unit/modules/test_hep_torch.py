import pytest
import unittest

from modules.hep_torch import hep_torch
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleTorch(unittest.TestCase):

    def test_opts(self):
        module = hep_torch()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_torch()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_torch()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_torch()
        self.assertIsInstance(module.producedEvents(), list)
