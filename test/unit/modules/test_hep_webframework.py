import pytest
import unittest

from modules.hep_webframework import hep_webframework
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleWebFramework(unittest.TestCase):

    def test_opts(self):
        module = hep_webframework()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_webframework()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_webframework()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_webframework()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_web_content_containing_webframework_string_should_create_url_web_framework_event(self):
        he = HawkEye(self.default_options)

        module = hep_webframework()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'URL_WEB_FRAMEWORK'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "Wordpress"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_webframework)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'TARGET_WEB_CONTENT'
        event_data = 'example data /wp-includes/ example data'
        event_module = 'hep_spider'
        source_event = evt
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = "https://hawkeye.net/"

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_web_content_not_containing_webframework_string_should_not_create_event(self):
        he = HawkEye(self.default_options)

        module = hep_webframework()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_webframework)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'TARGET_WEB_CONTENT'
        event_data = 'example data'
        event_module = 'example module'
        source_event = evt
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = "https://hawkeye.net/"

        result = module.handleEvent(evt)

        self.assertIsNone(result)

    def test_handleEvent_event_data_web_content_from_external_url_containing_webframework_string_should_not_create_event(self):
        he = HawkEye(self.default_options)

        module = hep_webframework()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_webframework)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'TARGET_WEB_CONTENT'
        event_data = 'example data /wp-includes/ example data'
        event_module = 'hep_spider'
        source_event = evt
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = "https://externalhost.local/"

        result = module.handleEvent(evt)

        self.assertIsNone(result)
