import pytest
import unittest

from modules.hep_slideshare import hep_slideshare
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleSlideshare(unittest.TestCase):

    def test_opts(self):
        module = hep_slideshare()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_slideshare()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_slideshare()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_slideshare()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_social_media_not_slideshare_profile_should_not_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_slideshare()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_slideshare)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'SOCIAL_MEDIA'
        event_data = 'Not SlideShare: example_username'
        event_module = 'example module'
        source_event = evt

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
