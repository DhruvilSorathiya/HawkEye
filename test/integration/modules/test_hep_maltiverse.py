import pytest
import unittest

from modules.hep_maltiverse import hep_maltiverse
from helib import HawkEye
from hawkeye import HawkEyeEvent, HawkEyeTarget


@pytest.mark.usefixtures
class TestModuleIntegrationMaltiverse(unittest.TestCase):

    @unittest.skip("todo")
    def test_handleEvent(self):
        he = HawkEye(self.default_options)

        module = hep_maltiverse()
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
