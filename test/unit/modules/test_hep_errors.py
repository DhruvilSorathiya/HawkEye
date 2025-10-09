import pytest
import unittest

from modules.hep_errors import hep_errors
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleErrors(unittest.TestCase):

    def test_opts(self):
        module = hep_errors()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_errors()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_errors()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_errors()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_should_only_handle_events_from_hep_spider(self):
        he = HawkEye(self.default_options)

        module = hep_errors()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_errors)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'TARGET_WEB_CONTENT'
        event_data = 'example data Internal Server Error example data'
        event_module = 'something else entirely'
        source_event = evt

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = 'https://hawkeye.net/'
        result = module.handleEvent(evt)

        self.assertIsNone(result)

    def test_handleEvent_should_only_handle_events_within_target_scope(self):
        he = HawkEye(self.default_options)

        module = hep_errors()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_errors)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'TARGET_WEB_CONTENT'
        event_data = 'example data Internal Server Error example data'
        event_module = 'hep_spider'
        source_event = evt

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = 'https://something.else.entirely/'
        result = module.handleEvent(evt)

        self.assertIsNone(result)

    def test_handleEvent_event_data_containing_error_string_should_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_errors()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'ERROR_MESSAGE'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = 'Generic Error'
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_errors)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)
        self.assertIsNone(result)

        event_type = 'TARGET_WEB_CONTENT'
        event_data = 'example data Internal Server Error example data'
        event_module = 'hep_spider'
        source_event = evt

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = 'https://hawkeye.net/'

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_not_containing_error_string_should_not_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_errors()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_errors)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        event_type = 'TARGET_WEB_CONTENT'
        event_data = 'example data'
        event_module = 'hep_spider'
        source_event = evt

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = 'https://hawkeye.net/'
        result = module.handleEvent(evt)

        self.assertIsNone(result)
