import pytest
import unittest

from modules.hep_cybercrimetracker import hep_cybercrimetracker
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleCybercrimetracker(unittest.TestCase):

    def test_opts(self):
        module = hep_cybercrimetracker()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_cybercrimetracker()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_cybercrimetracker()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_cybercrimetracker()
        self.assertIsInstance(module.producedEvents(), list)
