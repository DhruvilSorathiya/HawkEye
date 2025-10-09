import pytest
import unittest

from modules.hep_yandexdns import hep_yandexdns
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleYandexdns(unittest.TestCase):

    def test_opts(self):
        module = hep_yandexdns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_yandexdns()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_yandexdns()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_yandexdns()
        self.assertIsInstance(module.producedEvents(), list)
