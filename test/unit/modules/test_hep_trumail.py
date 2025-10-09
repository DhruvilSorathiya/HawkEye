import pytest
import unittest

from modules.hep_trumail import hep_trumail
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleTrumail(unittest.TestCase):

    def test_opts(self):
        module = hep_trumail()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_trumail()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_trumail()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_trumail()
        self.assertIsInstance(module.producedEvents(), list)
