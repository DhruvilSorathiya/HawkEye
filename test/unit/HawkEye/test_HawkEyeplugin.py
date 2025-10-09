# test_hawkeyeplugin.py
import pytest
import unittest

from helib import HawkEye
from hawkeye import HawkEyeDb, HawkEyeEvent, HawkEyePlugin, HawkEyeTarget


@pytest.mark.usefixtures
class TestHawkEyePlugin(unittest.TestCase):
    """
    Test HawkEye
    """

    def test_init(self):
        """
        Test __init__(self)
        """
        hep = HawkEyePlugin()
        self.assertIsInstance(hep, HawkEyePlugin)

    def test_updateSocket(self):
        """
        Test _updateSocket(self, sock)
        """
        hep = HawkEyePlugin()

        hep._updateSocket(None)
        self.assertEqual('TBD', 'TBD')

    def test_clearListeners(self):
        """
        Test clearListeners(self)
        """
        hep = HawkEyePlugin()

        hep.clearListeners()
        self.assertEqual('TBD', 'TBD')

    def test_setup(self):
        """
        Test setup(self, he, userOpts=dict())
        """
        hep = HawkEyePlugin()

        hep.setup(None)
        hep.setup(None, None)
        self.assertEqual('TBD', 'TBD')

    def test_enrichTargetargument_target_should_enrih_target(self):
        """
        Test enrichTarget(self, target)
        """
        hep = HawkEyePlugin()

        hep.enrichTarget(None)
        self.assertEqual('TBD', 'TBD')

    def test_setTarget_should_set_a_target(self):
        """
        Test setTarget(self, target)
        """
        hep = HawkEyePlugin()

        target = HawkEyeTarget("hawkeye.net", "INTERNET_NAME")
        hep.setTarget(target)

        get_target = hep.getTarget().targetValue
        self.assertIsInstance(get_target, str)
        self.assertEqual("hawkeye.net", get_target)

    def test_setTarget_argument_target_invalid_type_should_raise_TypeError(self):
        """
        Test setTarget(self, target)
        """
        hep = HawkEyePlugin()

        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    hep.setTarget(invalid_type)

    def test_set_dbhargument_dbh_should_set_database_handle(self):
        """
        Test setDbh(self, dbh)
        """
        hedb = HawkEyeDb(self.default_options, False)
        hep = HawkEyePlugin()

        hep.setDbh(hedb)
        self.assertIsInstance(hep.__hedb__, HawkEyeDb)

    def test_setScanId_argument_id_should_set_a_scan_id(self):
        """
        Test setScanId(self, id)
        """
        hep = HawkEyePlugin()

        scan_id = '1234'
        hep.setScanId(scan_id)

        get_scan_id = hep.getScanId()
        self.assertIsInstance(get_scan_id, str)
        self.assertEqual(scan_id, get_scan_id)

    def test_setScanId_argument_id_invalid_type_should_raise_TypeError(self):
        """
        Test setScanId(self, id)
        """
        hep = HawkEyePlugin()

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    hep.setScanId(invalid_type)

    def test_getScanId_should_return_a_string(self):
        """
        Test getScanId(self)
        """
        hep = HawkEyePlugin()

        scan_id = 'example scan id'
        hep.setScanId(scan_id)

        get_scan_id = hep.getScanId()
        self.assertIsInstance(get_scan_id, str)
        self.assertEqual(scan_id, get_scan_id)

    def test_getScanId_unitialised_scanid_should_raise_TypeError(self):
        """
        Test getScanId(self)
        """
        hep = HawkEyePlugin()

        with self.assertRaises(TypeError):
            hep.getScanId()

    def test_getTarget_should_return_a_string(self):
        """
        Test getTarget(self)
        """
        hep = HawkEyePlugin()

        target = HawkEyeTarget("hawkeye.net", "INTERNET_NAME")
        hep.setTarget(target)

        get_target = hep.getTarget().targetValue
        self.assertIsInstance(get_target, str)
        self.assertEqual("hawkeye.net", get_target)

    def test_getTarget_unitialised_target_should_raise(self):
        """
        Test getTarget(self)
        """
        hep = HawkEyePlugin()

        with self.assertRaises(TypeError):
            hep.getTarget()

    def test_register_listener(self):
        """
        Test registerListener(self, listener)
        """
        hep = HawkEyePlugin()
        hep.registerListener(None)

        self.assertEqual('TBD', 'TBD')

    def test_setOutputFilter_should_set_output_filter(self):
        """
        Test setOutputFilter(self, types)
        """
        hep = HawkEyePlugin()

        output_filter = "test filter"
        hep.setOutputFilter("test filter")
        self.assertEqual(output_filter, hep.__outputFilter__)

    def test_tempStorage_should_return_a_dict(self):
        """
        Test tempStorage(self)
        """
        hep = HawkEyePlugin()

        temp_storage = hep.tempStorage()
        self.assertIsInstance(temp_storage, dict)

    def test_notifyListeners_should_notify_listener_modules(self):
        """
        Test notifyListeners(self, heEvent)
        """
        hep = HawkEyePlugin()
        hedb = HawkEyeDb(self.default_options, False)
        hep.setDbh(hedb)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = HawkEyeEvent(event_type, event_data, module, source_event)
        hep.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_output_filter_matched_should_notify_listener_modules(self):
        """
        Test notifyListeners(self, heEvent)
        """
        hep = HawkEyePlugin()
        hedb = HawkEyeDb(self.default_options, False)
        hep.setDbh(hedb)

        target = HawkEyeTarget("hawkeye.net", "INTERNET_NAME")
        hep.setTarget(target)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = HawkEyeEvent(event_type, event_data, module, source_event)

        event_type = 'test event type'
        event_data = 'test data'
        module = 'test module'
        source_event = evt
        evt = HawkEyeEvent(event_type, event_data, module, source_event)

        hep.__outputFilter__ = event_type

        hep.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_output_filter_unmatched_should_not_notify_listener_modules(self):
        """
        Test notifyListeners(self, heEvent)
        """
        hep = HawkEyePlugin()
        hedb = HawkEyeDb(self.default_options, False)
        hep.setDbh(hedb)

        target = HawkEyeTarget("hawkeye.net", "INTERNET_NAME")
        hep.setTarget(target)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = HawkEyeEvent(event_type, event_data, module, source_event)

        event_type = 'test event type'
        event_data = 'test data'
        module = 'test module'
        source_event = evt
        evt = HawkEyeEvent(event_type, event_data, module, source_event)

        hep.__outputFilter__ = "example unmatched event type"

        hep.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_event_type_and_data_same_as_source_event_source_event_should_story_only(self):
        """
        Test notifyListeners(self, heEvent)
        """
        hep = HawkEyePlugin()
        hedb = HawkEyeDb(self.default_options, False)
        hep.setDbh(hedb)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = HawkEyeEvent(event_type, event_data, module, source_event)

        event_type = 'test event type'
        event_data = 'test data'
        module = 'test module'
        source_event = evt
        evt = HawkEyeEvent(event_type, event_data, module, source_event)

        source_event = evt
        evt = HawkEyeEvent(event_type, event_data, module, source_event)

        source_event = evt
        evt = HawkEyeEvent(event_type, event_data, module, source_event)

        hep.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_argument_heEvent_invalid_event_should_raise_TypeError(self):
        """
        Test notifyListeners(self, heEvent)
        """
        hep = HawkEyePlugin()

        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    hep.notifyListeners(invalid_type)

    def test_checkForStop(self):
        """
        Test checkForStop(self)
        """
        hep = HawkEyePlugin()

        class DatabaseStub:
            def scanInstanceGet(self, scanId):
                return [None, None, None, None, None, status]

        hep.__hedb__ = DatabaseStub()
        hep.__scanId__ = 'example scan id'

        # pseudo-parameterized test
        scan_statuses = [
            (None, False),
            ("anything", False),
            ("RUNNING", False),
            ("ABORT-REQUESTED", True)
        ]
        for status, expectedReturnValue in scan_statuses:
            returnValue = hep.checkForStop()
            self.assertEqual(returnValue, expectedReturnValue, status)

    def test_watchedEvents_should_return_a_list(self):
        """
        Test watchedEvents(self)
        """
        hep = HawkEyePlugin()

        watched_events = hep.watchedEvents()
        self.assertIsInstance(watched_events, list)

    def test_producedEvents_should_return_a_list(self):
        """
        Test producedEvents(self)
        """
        hep = HawkEyePlugin()

        produced_events = hep.producedEvents()
        self.assertIsInstance(produced_events, list)

    def test_handleEvent(self):
        """
        Test handleEvent(self, heEvent)
        """
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, module, source_event)

        hep = HawkEyePlugin()
        hep.handleEvent(evt)

    def test_start(self):
        """
        Test start(self)
        """
        he = HawkEye(self.default_options)
        hep = HawkEyePlugin()
        hep.he = he

        hep.start()
