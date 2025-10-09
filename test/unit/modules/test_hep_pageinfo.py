import pytest
import unittest

from modules.hep_pageinfo import hep_pageinfo
from helib import HawkEye


@pytest.mark.usefixtures
class TestModulePageInfo(unittest.TestCase):

    def test_opts(self):
        module = hep_pageinfo()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_pageinfo()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_pageinfo()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_pageinfo()
        self.assertIsInstance(module.producedEvents(), list)
