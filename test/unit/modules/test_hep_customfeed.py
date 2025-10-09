import pytest
import unittest

from modules.hep_customfeed import hep_customfeed
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleCustomfeed(unittest.TestCase):

    def test_opts(self):
        module = hep_customfeed()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_customfeed()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_customfeed()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_customfeed()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_feed_url_should_set_errorState(self):
        he = HawkEye(self.default_options)

        module = hep_customfeed()
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
