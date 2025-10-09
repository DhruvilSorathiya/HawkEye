import pytest
import unittest

from modules.hep_pgp import hep_pgp
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModulePgp(unittest.TestCase):

    def test_opts(self):
        module = hep_pgp()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        he = HawkEye(self.default_options)
        module = hep_pgp()
        module.setup(he, dict())

    def test_watchedEvents_should_return_list(self):
        module = hep_pgp()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = hep_pgp()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_keyserver_urls_should_set_errorState(self):
        he = HawkEye(self.default_options)

        module = hep_pgp()
        module.setup(he, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = HawkEyeTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = HawkEyeEvent(event_type, event_data, event_module, source_event)

        module.opts['keyserver_search1'] = ''
        module.opts['keyserver_search2'] = ''
        module.opts['keyserver_fetch1'] = ''
        module.opts['keyserver_fetch2'] = ''

        result = module.handleEvent(evt)

        self.assertIsNone(result)
        self.assertTrue(module.errorState)
