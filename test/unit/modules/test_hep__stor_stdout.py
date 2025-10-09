import pytest
import unittest

from modules.hep__stor_stdout import hep__stor_stdout
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleStor_stdout(unittest.TestCase):

    @unittest.skip("This module contains an extra private option")
    def test_opts(self):
        module = hep__stor_stdout()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep__stor_stdout()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep__stor_stdout()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep__stor_stdout()
        self.assertIsInstance(module.producedEvents(), list)
