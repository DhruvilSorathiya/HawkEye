import pytest
import unittest

from modules.hep_neutrinoapi import hep_neutrinoapi
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleNeutrinoapi(unittest.TestCase):

    def test_opts(self):
        module = hep_neutrinoapi()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_neutrinoapi()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_neutrinoapi()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_neutrinoapi()
        self.assertIsInstance(module.producedEvents(), list)

    def test_parseApiResponse_nonfatal_http_response_code_should_not_set_errorState(self):
        he = HawkEye(self.default_options)

        http_codes = ["200", "400"]
        for code in http_codes:
            with self.subTest(code=code):
                module = hep_neutrinoapi()
                module.setup(he, dict())
                result = module.parseApiResponse({"code": code, "content": None})
                self.assertIsNone(result)
                self.assertFalse(module.errorState)

    def test_parseApiResponse_fatal_http_response_error_code_should_set_errorState(self):
        he = HawkEye(self.default_options)

        # TODO: http_codes = ["401", "402", "403", "429", "500", "502", "503"]
        http_codes = ["403"]
        for code in http_codes:
            with self.subTest(code=code):
                module = hep_neutrinoapi()
                module.setup(he, dict())
                result = module.parseApiResponse({"code": code, "content": None})
                self.assertIsNone(result)
                self.assertTrue(module.errorState)

    def test_handleEvent_no_api_key_should_set_errorState(self):
        he = HawkEye(self.default_options)

        module = hep_neutrinoapi()
        module.setup(he, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
        self.assertTrue(module.errorState)
