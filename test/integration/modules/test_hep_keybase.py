import pytest
import unittest

from modules.hep_keybase import hep_keybase
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleIntegrationKeybase(unittest.TestCase):

    @unittest.skip("todo")
    def test_handleEvent(self):
        he = HawkEye(self.default_options)

        module = hep_keybase()
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

        result = module.handleEvent(evt)

        self.assertIsNone(result)
