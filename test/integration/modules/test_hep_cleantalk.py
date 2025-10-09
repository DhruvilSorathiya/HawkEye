import pytest
import unittest

from modules.hep_cleantalk import hep_cleantalk
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleIntegrationcleantalk(unittest.TestCase):

    def test_handleEvent_event_data_safe_ip_address_not_blocked_should_not_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_cleantalk()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        module.opts['_fetchtimeout'] = 15
        module.optdescs['_fetchtimeout'] = ''
        module.opts['_useragent'] = ''
        module.optdescs['_useragent'] = ''

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_cleantalk)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'IP_ADDRESS'
        event_data = '1.0.0.1'
        event_module = 'example module'
        source_event = evt

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
