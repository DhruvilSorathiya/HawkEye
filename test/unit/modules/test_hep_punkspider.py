import pytest
import unittest

from modules.hep_punkspider import hep_punkspider
from helib import HawkEye


@pytest.mark.usefixtures
class TestModulePunkhawk(unittest.TestCase):

    def test_opts(self):
        module = hep_punkspider()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_punkspider()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_punkspider()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_punkspider()
        self.assertIsInstance(module.producedEvents(), list)

    def test_parseApiResponse_nonfatal_http_response_code_should_not_set_errorState(self):
        he = HawkEye(self.default_options)

        http_codes = ["200", "404"]
        for code in http_codes:
            with self.subTest(code=code):
                module = hep_punkspider()
                module.setup(he, dict())
                result = module.parseApiResponse({"code": code, "content": None})
                self.assertIsNone(result)
                self.assertFalse(module.errorState)

    def test_parseApiResponse_fatal_http_response_error_code_should_set_errorState(self):
        he = HawkEye(self.default_options)

        http_codes = ["401", "402", "403", "429", "500", "502", "503"]
        for code in http_codes:
            with self.subTest(code=code):
                module = hep_punkspider()
                module.setup(he, dict())
                result = module.parseApiResponse({"code": code, "content": None})
                self.assertIsNone(result)
                self.assertTrue(module.errorState)
