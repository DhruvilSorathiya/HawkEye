import pytest
import unittest

from modules.hep_social import hep_social
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleSocial(unittest.TestCase):

    def test_opts(self):
        module = hep_social()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_social()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_social()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_social()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_url_containing_social_media_profile_should_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_social()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'SOCIAL_MEDIA'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "LinkedIn (Individual): <HEURL>https://linkedin.com/in/hawkeye</HEURL>"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_social)

        event_type = 'ROOT'
        event_data = 'https://linkedin.com/in/hawkeye'
        event_module = ''
        source_event = ''

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_url_not_containing_social_media_profile_should_not_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_social()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_social)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
