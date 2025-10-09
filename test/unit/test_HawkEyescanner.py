# test_hawkeyescanner.py
import pytest
import unittest
import uuid

from hescan import HawkEyeScanner


@pytest.mark.usefixtures
class TestHawkEyeScanner(unittest.TestCase):
    """
    Test HawkEyeScanStatus
    """

    def test_init_argument_start_false_should_create_a_scan_without_starting_the_scan(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        hescan = HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "INTERNET_NAME", module_list, opts, start=False)
        self.assertIsInstance(hescan, HawkEyeScanner)
        self.assertEqual(hescan.status, "INITIALIZING")

    def test_init_argument_start_true_with_no_valid_modules_should_set_scanstatus_to_failed(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['invalid module']

        hescan = HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "INTERNET_NAME", module_list, opts, start=True)
        self.assertIsInstance(hescan, HawkEyeScanner)
        self.assertEqual(hescan.status, "ERROR-FAILED")

    def test_init_argument_scanName_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    HawkEyeScanner(invalid_type, scan_id, "hawkeye.net", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_scanName_as_empty_string_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        with self.assertRaises(ValueError):
            HawkEyeScanner("", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_scanId_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        module_list = ['hep__stor_db']

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    HawkEyeScanner("example scan name", invalid_type, "hawkeye.net", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_scanId_as_empty_string_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = ""
        module_list = ['hep__stor_db']

        with self.assertRaises(ValueError):
            HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_targetValue_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    HawkEyeScanner("example scan name", scan_id, invalid_type, "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_targetValue_as_empty_string_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        with self.assertRaises(ValueError):
            HawkEyeScanner("example scan name", scan_id, "", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_targetType_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    HawkEyeScanner("example scan name", scan_id, "hawkeye.net", invalid_type, module_list, self.default_options, start=False)

    def test_init_argument_targetType_invalid_value_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        target_type = ""
        with self.assertRaises(ValueError):
            HawkEyeScanner("example scan name", scan_id, "hawkeye.net", target_type, module_list, self.default_options, start=False)

        target_type = "INVALID_TARGET_TYPE"
        with self.assertRaises(ValueError):
            HawkEyeScanner("example scan name", scan_id, "hawkeye.net", target_type, module_list, self.default_options, start=False)

    def test_init_argument_moduleList_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())

        invalid_types = [None, "", dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", invalid_type, self.default_options, start=False)

    def test_init_argument_moduleList_as_empty_list_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = list()

        with self.assertRaises(ValueError):
            HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_globalOpts_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        invalid_types = [None, "", list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, invalid_type, start=False)

    def test_init_argument_globalOpts_as_empty_dict_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        with self.assertRaises(ValueError):
            HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, dict(), start=False)

    def test_init_argument_globalOpts_proxy_invalid_proxy_type_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        opts = self.default_options
        opts['_socks1type'] = 'invalid proxy type'
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        with self.assertRaises(ValueError):
            HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, opts, start=False)

    def test_init_argument_globalOpts_proxy_type_without_host_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        opts = self.default_options
        opts['_socks1type'] = 'HTTP'
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        with self.assertRaises(ValueError):
            HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, opts, start=False)

    def test_init_argument_globalOpts_proxy_should_set_proxy(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        opts = self.default_options
        opts['_socks1type'] = 'HTTP'
        opts['_socks2addr'] = '127.0.0.1'
        opts['_socks3port'] = '8080'
        opts['_socks4user'] = 'user'
        opts['_socks5pwd'] = 'password'
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, opts, start=False)

        self.assertEqual('TBD', 'TBD')

    def test_init_argument_globalOpts_proxy_without_port_should_set_proxy(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        opts = self.default_options
        opts['_socks1type'] = 'HTTP'
        opts['_socks2addr'] = '127.0.0.1'
        opts['_socks3port'] = ''
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, opts, start=False)

        self.assertEqual('TBD', 'TBD')

    def test_attribute_scanId_should_return_scan_id_as_a_string(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        hescan = HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, opts, start=False)
        self.assertIsInstance(hescan, HawkEyeScanner)

        get_id = hescan.scanId
        self.assertIsInstance(get_id, str)
        self.assertEqual(scan_id, get_id)

    def test_attribute_status_should_return_status_as_a_string(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        hescan = HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, opts, start=False)
        self.assertIsInstance(hescan, HawkEyeScanner)

        status = hescan.status
        self.assertIsInstance(status, str)

    def test__setStatus_argument_status_of_invalid_type_should_raise_TypeError(self):
        """
        Test __setStatus(self, status, started=None, ended=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        hescan = HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, opts, start=False)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    hescan._HawkEyeScanner__setStatus(invalid_type)

    def test__setStatus_argument_status_with_blank_value_should_raise_ValueError(self):
        """
        Test __setStatus(self, status, started=None, ended=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['hep__stor_db']

        hescan = HawkEyeScanner("example scan name", scan_id, "hawkeye.net", "IP_ADDRESS", module_list, opts, start=False)
        with self.assertRaises(ValueError):
            hescan._HawkEyeScanner__setStatus("example invalid scan status")
