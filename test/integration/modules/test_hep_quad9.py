import pytest
import unittest

from modules.hep_quad9 import hep_quad9
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleIntegrationQuad9(unittest.TestCase):

    def test_handleEvent_event_data_safe_internet_name_not_blocked_should_not_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_quad9()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_quad9)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'INTERNET_NAME'
        event_data = 'quad9.net'
        event_module = 'example module'
        source_event = evt

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
