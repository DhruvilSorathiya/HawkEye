import pytest
import unittest

from modules.hep__stor_db import hep__stor_db
from helib import HawkEye


@pytest.mark.usefixtures
class TestModuleStor_db(unittest.TestCase):

    @unittest.skip("This module contains an extra private option")
    def test_opts(self):
        module = hep__stor_db()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep__stor_db()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep__stor_db()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep__stor_db()
        self.assertIsInstance(module.producedEvents(), list)
