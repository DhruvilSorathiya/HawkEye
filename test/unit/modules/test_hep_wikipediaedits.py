import pytest
import unittest

from modules.hep_wikipediaedits import hep_wikipediaedits
from helib import HawkEye


@pytest.mark.usefixtures
class TestModulewikipediaedits(unittest.TestCase):

    def test_opts(self):
        module = hep_wikipediaedits()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_wikipediaedits()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_wikipediaedits()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_wikipediaedits()
        self.assertIsInstance(module.producedEvents(), list)
