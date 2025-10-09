import pytest
import unittest

from modules.hep_hosting import hep_hosting
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleIntegrationHosting(unittest.TestCase):

    @unittest.skip("todo")
    def test_handleEvent_event_data_ip_address_hosted_should_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_hosting()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'PROVIDER_HOSTING'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "Amazon AWS: http://www.amazon.com/aws/"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_hosting)

        event_type = 'ROOT'
        event_data = '3.1.1.1'
        event_module = ''
        source_event = ''

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    @unittest.skip("todo")
    def test_handleEvent_event_data_ip_address_not_hosted_should_not_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_hosting()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_hosting)

        event_type = 'ROOT'
        event_data = '127.0.0.1'
        event_module = ''
        source_event = ''

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
