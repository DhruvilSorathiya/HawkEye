import pytest
import unittest

from modules.hep_hashes import hep_hashes
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleHashes(unittest.TestCase):

    def test_opts(self):
        module = hep_hashes()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_hashes()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_hashes()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_hashes()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_containing_hashes_string_should_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_hashes()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'HASH'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "[MD5] e17cff4eb3e8fbe6ca3b83fb47532dba"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_hashes)

        event_type = 'ROOT'
        event_data = 'example data e17cff4eb3e8fbe6ca3b83fb47532dba example data'
        event_module = ''
        source_event = ''

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_not_containing_hashes_string_should_not_return_event(self):
        he = HawkEye(self.default_options)

        module = hep_hashes()
        module.setup(he, dict())

        target_value = 'hawkeye.net'
        target_type = 'INTERNET_NAME'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, hep_hashes)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''

        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
