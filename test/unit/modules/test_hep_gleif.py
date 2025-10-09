import pytest
import unittest

from modules.hep_gleif import hep_gleif
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleGleif(unittest.TestCase):

    def test_opts(self):
        module = hep_gleif()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_gleif()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_gleif()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_gleif()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_invalid_lei_should_not_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_gleif()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_gleif)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        event_type = 'LEI'
        event_data = 'invalid LEI'
        event_module = 'example module'
        source_event = evt
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
