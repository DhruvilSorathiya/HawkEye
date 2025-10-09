import pytest
import unittest

from modules.hep_myspace import hep_myspace
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleMyspace(unittest.TestCase):

    def test_opts(self):
        module = hep_myspace()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_myspace()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_myspace()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_myspace()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_social_media_not_myspace_profile_should_not_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_myspace()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_myspace)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'SOCIAL_MEDIA'
        event_data = 'Not MySpace: example_username'
        event_module = 'example module'
        source_event = evt

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
