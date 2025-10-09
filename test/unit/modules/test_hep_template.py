import pytest
import unittest

from modules.hep_template import hep_template
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleTemplate(unittest.TestCase):

    def test_opts(self):
        module = hep_template()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_template()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_template()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_template()
        self.assertIsInstance(module.producedEvents(), list)
