# test_hawkeye.py
import pytest
import unittest

from helib import HawkEye


@pytest.mark.usefixtures
class TestHawkEye(unittest.TestCase):

    default_modules = [
        "hep_binstring",
        "hep_company",
        "hep_cookie",
        "hep_countryname",
        "hep_creditcard",
        "hep_email",
        "hep_errors",
        "hep_ethereum",
        "hep_filemeta",
        "hep_hashes",
        "hep_iban",
        "hep_names",
        "hep_pageinfo",
        "hep_phone",
        "hep_webanalytics"
    ]

    test_tlds = "// ===BEGIN ICANN DOMAINS===\n\ncom\nnet\norg\n\n// // ===END ICANN DOMAINS===\n"

    def test_init_argument_options_of_invalid_type_should_raise_TypeError(self):
        invalid_types = [None, "", bytes(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type), self.assertRaises(TypeError):
                HawkEye(invalid_type)

    def test_init_argument_options_with_empty_dict(self):
        he = HawkEye(dict())
        self.assertIsInstance(he, HawkEye)

    def test_init_argument_options_with_default_options(self):
        he = HawkEye(self.default_options)
        self.assertIsInstance(he, HawkEye)

    def test_attribute_dbh(self):
        he = HawkEye(dict())

        he.dbh = 'new handle'
        self.assertEqual('new handle', he.dbh)

    def test_attribute_scanId(self):
        he = HawkEye(dict())

        he.scanId = 'new guid'
        self.assertEqual('new guid', he.scanId)

    def test_attribute_socksProxy(self):
        he = HawkEye(dict())

        he.socksProxy = 'new socket'
        self.assertEqual('new socket', he.socksProxy)

    def test_optValueToData_should_return_data_as_string(self):
        he = HawkEye(self.default_options)

        test_string = "example string"
        opt_data = he.optValueToData(test_string)
        self.assertIsInstance(opt_data, str)
        self.assertEqual(test_string, opt_data)

    def test_optValueToData_argument_val_filename_should_return_file_contents_as_string(self):
        he = HawkEye(self.default_options)

        test_string = "@VERSION"
        opt_data = he.optValueToData(test_string)
        self.assertIsInstance(opt_data, str)
        self.assertTrue(opt_data.startswith("HawkEye"))

    def test_optValueToData_argument_val_invalid_type_should_return_None(self):
        he = HawkEye(self.default_options)

        invalid_types = [None, bytes(), list(), int(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                opt_data = he.optValueToData(invalid_type)
                self.assertEqual(opt_data, None)

    def test_error(self):
        he = HawkEye(self.default_options)

        he.error(None)
        self.assertEqual('TBD', 'TBD')

    def test_fatal_should_exit(self):
        he = HawkEye(self.default_options)

        with self.assertRaises(SystemExit) as cm:
            he.fatal(None)

        self.assertEqual(cm.exception.code, -1)

    def test_status(self):
        he = HawkEye(self.default_options)

        he.status(None)
        self.assertEqual('TBD', 'TBD')

    def test_info(self):
        he = HawkEye(self.default_options)

        he.info(None)
        self.assertEqual('TBD', 'TBD')

    def test_debug(self):
        he = HawkEye(self.default_options)

        he.debug(None)
        self.assertEqual('TBD', 'TBD')

    def test_hash_string_should_return_a_string(self):
        he = HawkEye(dict())

        hash_string = he.hashstring('example string')
        self.assertIsInstance(hash_string, str)
        self.assertEqual("aedfb92b3053a21a114f4f301a02a3c6ad5dff504d124dc2cee6117623eec706", hash_string)

    def test_cache_get_should_return_a_string(self):
        he = HawkEye(dict())

        label = 'test-cache-label'
        data = 'test-cache-data'

        he.cachePut(label, data)

        cache_get = he.cacheGet(label, he.opts.get('cacheperiod', 0))
        self.assertIsInstance(cache_get, str)
        self.assertEqual(data, cache_get)

    def test_config_serialize_invalid_opts_should_raise(self):
        he = HawkEye(dict())

        with self.assertRaises(TypeError):
            he.configSerialize(None, None)

    def test_config_serialize_should_return_a_dict(self):
        he = HawkEye(dict())

        config = he.configSerialize(dict(), None)
        self.assertIsInstance(config, dict)

    def test_config_unserialize_invalid_opts_should_raise(self):
        he = HawkEye(dict())

        with self.assertRaises(TypeError):
            he.configUnserialize(None, dict(), None)

    def test_config_unserialize_invalid_reference_point_should_raise(self):
        he = HawkEye(dict())

        with self.assertRaises(TypeError):
            he.configUnserialize(dict(), None, None)

    def test_config_unserialize_should_return_a_dict(self):
        he = HawkEye(dict())

        config = he.configUnserialize(dict(), dict(), True)
        self.assertIsInstance(config, dict)

    def test_cache_get_invalid_label_should_return_none(self):
        he = HawkEye(dict())

        cache_get = he.cacheGet('', he.opts.get('cacheperiod', 0))
        self.assertEqual(None, cache_get)

    def test_cache_get_invalid_timeout_should_return_none(self):
        he = HawkEye(dict())

        cache_get = he.cacheGet('', None)
        self.assertEqual(None, cache_get)

    def test_modulesProducing_argument_events_should_return_a_list(self):
        he = HawkEye(self.default_options)

        events = ['IP_ADDRESS', 'DOMAIN_NAME', 'INTERNET_NAME']

        modules_producing = he.modulesProducing(events)
        self.assertIsInstance(modules_producing, list)

    def test_modulesProducing_argument_events_with_empty_value_should_return_a_list(self):
        he = HawkEye(dict())

        modules_producing = he.modulesProducing(list())
        self.assertIsInstance(modules_producing, list)

    def test_modulesConsuming_argument_events_should_return_a_list(self):
        he = HawkEye(self.default_options)

        events = ['IP_ADDRESS', 'DOMAIN_NAME', 'INTERNET_NAME']

        modules_consuming = he.modulesConsuming(events)
        self.assertIsInstance(modules_consuming, list)

    def test_modulesConsuming_argument_events_with_empty_value_should_return_a_list(self):
        he = HawkEye(dict())

        modules_consuming = he.modulesConsuming(list())
        self.assertIsInstance(modules_consuming, list)

    def test_eventsFromModules_argument_modules_with_empty_value_should_return_a_list(self):
        he = HawkEye(self.default_options)

        events_from_modules = he.eventsFromModules(list())
        self.assertIsInstance(events_from_modules, list)

    def test_eventsFromModules_argument_modules_should_return_events(self):
        he = HawkEye(self.default_options)

        events_from_modules = he.eventsFromModules(self.default_modules)
        self.assertIsInstance(events_from_modules, list)

    def test_eventsToModules_argument_modules_with_empty_value_should_return_a_list(self):
        he = HawkEye(self.default_options)

        events_to_modules = he.eventsToModules(list())
        self.assertIsInstance(events_to_modules, list)

    def test_eventsToModules_argument_modules_should_return_events(self):
        he = HawkEye(self.default_options)

        events_to_modules = he.eventsToModules(self.default_modules)
        self.assertIsInstance(events_to_modules, list)

    def test_url_fqdn_should_return_a_string(self):
        he = HawkEye(dict())

        fqdn = he.urlFQDN('http://localhost.local')
        self.assertIsInstance(fqdn, str)
        self.assertEqual("localhost.local", fqdn)

    def test_domain_keyword_should_return_a_string(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        keyword = he.domainKeyword('www.hawkeye.net', he.opts.get('_internettlds'))
        self.assertIsInstance(keyword, str)
        self.assertEqual('hawkeye', keyword)

        keyword = he.domainKeyword('spiderfööt.example', he.opts.get('_internettlds'))
        self.assertIsInstance(keyword, str)
        self.assertEqual('spiderfööt', keyword)

    def test_domain_keyword_invalid_domain_should_return_none(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        keyword = he.domainKeyword("", he.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = he.domainKeyword([], he.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = he.domainKeyword(None, he.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = he.domainKeyword("net", he.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = he.domainKeyword(".net", he.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = he.domainKeyword(".", he.opts.get('_internettlds'))
        self.assertEqual(None, keyword)

    def test_domain_keywords_should_return_a_set(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        domain_list = ['www.example.com', 'localhost.local']
        keywords = he.domainKeywords(domain_list, he.opts.get('_internettlds'))
        self.assertIsInstance(keywords, set)
        self.assertIn('localhost', keywords)
        self.assertIn('example', keywords)

    def test_domain_keywords_invalid_domainlist_should_return_a_set(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        keywords = he.domainKeywords("", he.opts.get('_internettlds'))
        self.assertIsInstance(keywords, set)
        keywords = he.domainKeywords([], he.opts.get('_internettlds'))
        self.assertIsInstance(keywords, set)
        keywords = he.domainKeywords(None, he.opts.get('_internettlds'))
        self.assertIsInstance(keywords, set)

    def test_host_domain_invalid_host_should_return_none(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        host_domain = he.hostDomain(None, he.opts.get('_internettlds'))
        self.assertEqual(None, host_domain)

    def test_host_domain_should_return_a_string(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        host_domain = he.hostDomain('www.hawkeye.net', he.opts.get('_internettlds'))
        self.assertIsInstance(host_domain, str)
        self.assertEqual('hawkeye.net', host_domain)

        host_domain = he.hostDomain('hawkeye.net', he.opts.get('_internettlds'))
        self.assertIsInstance(host_domain, str)
        self.assertEqual('hawkeye.net', host_domain)

        host_domain = he.hostDomain('abc.www.hawkeye.net', he.opts.get('_internettlds'))
        self.assertIsInstance(host_domain, str)
        self.assertEqual('hawkeye.net', host_domain)

    def test_host_domain_invalid_tldlist_should_return_none(self):
        he = HawkEye(dict())

        host_domain = he.hostDomain('hawkeye.net', None)
        self.assertEqual(None, host_domain)

    def test_is_domain_valid_domain_should_return_true(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        is_domain = he.isDomain('hawkeye.net', he.opts.get('_internettlds'))
        self.assertIsInstance(is_domain, bool)
        self.assertTrue(is_domain)

    def test_is_domain_invalid_domain_should_return_false(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                is_domain = he.isDomain(invalid_type, he.opts.get('_internettlds'))
                self.assertIsInstance(is_domain, bool)
                self.assertFalse(is_domain)

        is_domain = he.isDomain("local", he.opts.get('_internettlds'))
        self.assertIsInstance(is_domain, bool)
        self.assertFalse(is_domain)

        is_domain = he.isDomain("hawkeye.net\n.com", he.opts.get('_internettlds'))
        self.assertIsInstance(is_domain, bool)
        self.assertFalse(is_domain)

    def test_is_domain_invalid_tldlist_should_return_false(self):
        he = HawkEye(self.default_options)

        is_domain = he.isDomain('hawkeye.net', None)
        self.assertIsInstance(is_domain, bool)
        self.assertFalse(is_domain)

    def test_is_domain_invalid_tld_should_return_false(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        is_domain = he.isDomain('hawkeye.not_a_tld', he.opts.get('_internettlds'))
        self.assertIsInstance(is_domain, bool)
        self.assertFalse(is_domain)

    def test_valid_host_invalid_tldlist_should_return_false(self):
        he = HawkEye(self.default_options)

        is_host = he.validHost('hawkeye.net', None)
        self.assertIsInstance(is_host, bool)
        self.assertFalse(is_host)

    def test_valid_host_valid_host_should_return_true(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        is_host = he.validHost('hawkeye.net', he.opts.get('_internettlds'))
        self.assertIsInstance(is_host, bool)
        self.assertTrue(is_host)

    def test_valid_host_invalid_host_should_return_false(self):
        he = HawkEye(self.default_options)
        he.opts['_internettlds'] = self.test_tlds

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                is_valid = he.validHost(invalid_type, he.opts.get('_internettlds'))
                self.assertIsInstance(is_valid, bool)
                self.assertFalse(is_valid)

        is_valid = he.validHost("local", he.opts.get('_internettlds'))
        self.assertIsInstance(is_valid, bool)
        self.assertFalse(is_valid)

        is_valid = he.validHost('something.gif', he.opts.get('_internettlds'))
        self.assertIsInstance(is_valid, bool)
        self.assertFalse(is_valid)

        is_valid = he.validHost(".", he.opts.get('_internettlds'))
        self.assertIsInstance(is_valid, bool)
        self.assertFalse(is_valid)

        is_valid = he.validHost("hawkeye.net\n.com", he.opts.get('_internettlds'))
        self.assertIsInstance(is_valid, bool)
        self.assertFalse(is_valid)

    def test_valid_ip_should_return_a_boolean(self):
        he = HawkEye(dict())

        valid_ip = he.validIP('0.0.0.0')
        self.assertIsInstance(valid_ip, bool)
        self.assertTrue(valid_ip)

    def test_valid_ip6_should_return_a_boolean(self):
        he = HawkEye(dict())

        valid_ip6 = he.validIP6('::1')
        self.assertIsInstance(valid_ip6, bool)
        self.assertTrue(valid_ip6)

    def test_valid_ip_network_should_return_a_boolean(self):
        he = HawkEye(dict())

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                valid_ip_network = he.validIpNetwork(invalid_type)
                self.assertIsInstance(valid_ip_network, bool)
                self.assertFalse(valid_ip_network)

        valid_ip_network = he.validIpNetwork("/")
        self.assertIsInstance(valid_ip_network, bool)
        self.assertFalse(valid_ip_network)

        valid_ip_network = he.validIpNetwork('0.0.0.0/0')
        self.assertIsInstance(valid_ip_network, bool)
        self.assertTrue(valid_ip_network)

    def test_isPublicIpAddress_argument_ip_public_ip_address_should_return_True(self):
        he = HawkEye(dict())
        self.assertTrue(he.isPublicIpAddress('1.1.1.1'))
        self.assertTrue(he.isPublicIpAddress('8.8.8.8'))

    def test_isPublicIpAddress_argument_ip_nonpublic_ip_address_should_return_False(self):
        he = HawkEye(dict())

        ips = [
            '0.0.0.0',
            '127.0.0.1',
            '10.1.1.1',
            '172.16.1.1',
            '192.168.1.1',
            '255.240.0.0',
            '172.31.255.255',
            '224.0.1.0',
            '255.255.255.255',
            '169.254.0.1',
            '253.0.0.1',
            '::1',
            'ff00::1',
        ]
        for ip in ips:
            with self.subTest(ip=ip):
                self.assertFalse(he.isPublicIpAddress(ip))

    def test_isPublicIpAddress_argument_ip_invalid_ip_address_should_return_False(self):
        he = HawkEye(dict())
        self.assertFalse(he.isPublicIpAddress('invalid ip address'))

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                self.assertFalse(he.isPublicIpAddress(invalid_type))

    def test_normalizeDNS_should_strip_trailing_dots(self):
        he = HawkEye(self.default_options)
        dns = he.normalizeDNS(["example.local.", ["hawkeye.net."]])
        self.assertIsInstance(dns, list)
        self.assertIn("example.local", dns)
        self.assertIn("hawkeye.net", dns)

    def test_normalizeDNS_should_return_list(self):
        he = HawkEye(self.default_options)

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                dns = he.normalizeDNS(invalid_type)
                self.assertIsInstance(dns, list)

    def test_resolve_host_should_return_list(self):
        he = HawkEye(self.default_options)

        addrs = he.resolveHost('one.one.one.one')
        self.assertIsInstance(addrs, list)
        self.assertTrue(addrs)
        self.assertIn('1.1.1.1', addrs)

        addrs = he.resolveHost(None)
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

    def test_resolve_ip_should_return_list(self):
        he = HawkEye(self.default_options)

        addrs = he.resolveIP('1.1.1.1')
        self.assertIsInstance(addrs, list)
        self.assertTrue(addrs)
        self.assertIn('one.one.one.one', addrs)

        addrs = he.resolveIP('2606:4700:4700::1001')
        self.assertIsInstance(addrs, list)
        self.assertTrue(addrs)
        self.assertIn('one.one.one.one', addrs)

        addrs = he.resolveIP(None)
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

        addrs = he.resolveIP([])
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

        addrs = he.resolveIP("")
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

    def test_resolve_host6_should_return_a_list(self):
        he = HawkEye(self.default_options)

        addrs = he.resolveHost6('one.one.one.one')
        self.assertIsInstance(addrs, list)
        self.assertTrue(addrs)
        # TODO: Re-enable this once GitHub runners support IPv6
        # https://github.com/actions/virtual-environments/issues/668
        # self.assertIn('2606:4700:4700::1001', addrs)
        # self.assertIn('2606:4700:4700::1111', addrs)

        addrs = he.resolveHost6(None)
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

    def test_validate_ip_should_return_bool(self):
        he = HawkEye(self.default_options)

        validate_ip = he.validateIP(None, None)
        self.assertIsInstance(validate_ip, bool)
        self.assertFalse(validate_ip)

        validate_ip = he.validateIP('one.one.one.one', '1.1.1.1')
        self.assertIsInstance(validate_ip, bool)
        self.assertTrue(validate_ip)

    @unittest.skip("todo")
    def test_safe_socket(self):
        he = HawkEye(self.default_options)
        he.safeSocket(None, None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_safe_ssl_socket(self):
        he = HawkEye(self.default_options)

        he.safeSSLSocket(None, None, None, None)
        self.assertEqual('TBD', 'TBD')

    def test_parse_cert_should_return_a_dict(self):
        he = HawkEye(self.default_options)

        cert = "-----BEGIN CERTIFICATE-----\r\nMIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0NlowSjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMTGkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EFq6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWAa6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIGCCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNvbTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9kc3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAwVAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcCARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwuY3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsFAAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJouM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwuX4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlGPfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\r\n-----END CERTIFICATE-----"

        parse_cert = he.parseCert(cert)
        self.assertIsInstance(parse_cert, dict)

        parse_cert = he.parseCert(cert, 'hawkeye.net')
        self.assertIsInstance(parse_cert, dict)

    def test_parse_cert_invalid_cert_should_return_none(self):
        he = HawkEye(self.default_options)

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_cert = he.parseCert(invalid_type, 'hawkeye.net', 30)
                self.assertEqual(None, parse_cert)

    def test_parse_cert_invalid_fqdn_should_return_none(self):
        he = HawkEye(self.default_options)

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_cert = he.parseCert(None, invalid_type, 30)
                self.assertEqual(None, parse_cert)

    def test_parse_cert_invalid_expiringdays_should_return_none(self):
        he = HawkEye(self.default_options)

        invalid_types = [None, "", bytes(), list()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_cert = he.parseCert(None, 'hawkeye.net', invalid_type)
                self.assertEqual(None, parse_cert)

    def test_get_session_should_return_a_session(self):
        he = HawkEye(self.default_options)
        session = he.getSession()
        self.assertIn("requests.sessions.Session", str(session))

    def test_remove_url_creds_should_remove_credentials_from_url(self):
        url = "http://local/?key=secret&pass=secret&user=secret&password=secret"

        he = HawkEye(self.default_options)
        new_url = he.removeUrlCreds(url)
        self.assertNotIn("secret", new_url)

    def test_isValidLocalOrLoopbackIp_argument_ip_valid_local_or_loopback_should_return_True(self):
        he = HawkEye(self.default_options)
        self.assertTrue(he.isValidLocalOrLoopbackIp('127.0.0.1'))
        self.assertTrue(he.isValidLocalOrLoopbackIp('127.0.0.2'))
        self.assertTrue(he.isValidLocalOrLoopbackIp('::1'))
        self.assertTrue(he.isValidLocalOrLoopbackIp('10.1.1.1'))
        self.assertTrue(he.isValidLocalOrLoopbackIp('fdd1:a677:c70c:b8c5:1234:1234:1234:1234'))

    def test_isValidLocalOrLoopbackIp_argument_ip_remote_ip_should_return_False(self):
        he = HawkEye(self.default_options)
        self.assertFalse(he.isValidLocalOrLoopbackIp('1.1.1.1'))
        self.assertFalse(he.isValidLocalOrLoopbackIp('2606:4700:4700::1111'))

    def test_isValidLocalOrLoopbackIp_argument_ip_invalid_ip_should_return_False(self):
        he = HawkEye(self.default_options)
        self.assertFalse(he.isValidLocalOrLoopbackIp('0'))
        self.assertFalse(he.isValidLocalOrLoopbackIp('invalid ip address'))

    def test_useProxyForUrl_argument_url_with_private_host_should_return_False(self):
        opts = self.default_options

        proxy_host = 'proxy.hawkeye.net'

        opts['_socks1type'] = '5'
        opts['_socks2addr'] = proxy_host
        opts['_socks3port'] = '8080'

        he = HawkEye(opts)
        self.assertFalse(he.useProxyForUrl('10.1.1.1'))
        self.assertFalse(he.useProxyForUrl('172.16.1.1'))
        self.assertFalse(he.useProxyForUrl('192.168.1.1'))
        self.assertFalse(he.useProxyForUrl('127.0.0.1'))
        self.assertFalse(he.useProxyForUrl('localhost'))
        self.assertFalse(he.useProxyForUrl('test.local'))

    def test_useProxyForUrl_argument_url_with_proxy_host_should_return_False(self):
        opts = self.default_options

        proxy_host = 'proxy.hawkeye.net'

        opts['_socks1type'] = '5'
        opts['_socks2addr'] = proxy_host
        opts['_socks3port'] = '8080'

        he = HawkEye(opts)
        self.assertFalse(he.useProxyForUrl(proxy_host))

    def test_useProxyForUrl_argument_url_with_public_host_should_return_True(self):
        opts = self.default_options

        proxy_host = 'proxy.hawkeye.net'

        opts['_socks1type'] = '5'
        opts['_socks2addr'] = proxy_host
        opts['_socks3port'] = '8080'

        he = HawkEye(opts)
        self.assertTrue(he.useProxyForUrl('hawkeye.net'))
        self.assertTrue(he.useProxyForUrl('1.1.1.1'))

    def test_fetchUrl_argument_url_should_return_http_response_as_dict(self):
        he = HawkEye(self.default_options)

        res = he.fetchUrl("https://hawkeye.net/")
        self.assertIsInstance(res, dict)
        self.assertEqual(res['code'], "200")
        self.assertNotEqual(res['content'], None)

    def test_fetchUrl_argument_headOnly_should_return_http_response_as_dict(self):
        he = HawkEye(self.default_options)

        res = he.fetchUrl("https://hawkeye.net/", headOnly=True)
        self.assertIsInstance(res, dict)
        self.assertEqual(res['code'], "301")
        self.assertEqual(res['content'], None)

    def test_fetchUrl_argument_url_invalid_type_should_return_none(self):
        he = HawkEye(self.default_options)

        invalid_types = [None, list(), bytes(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                res = he.fetchUrl(invalid_type)
                self.assertEqual(None, res)

    def test_fetchUrl_argument_url_invalid_url_should_return_None(self):
        he = HawkEye(self.default_options)

        res = he.fetchUrl("")
        self.assertEqual(None, res)

        res = he.fetchUrl("://hawkeye.net/")
        self.assertEqual(None, res)

        res = he.fetchUrl("file:///etc/hosts")
        self.assertEqual(None, res)

        res = he.fetchUrl("irc://hawkeye.net:6697/")
        self.assertEqual(None, res)

    def test_check_dns_wildcard_invalid_target_should_return_none(self):
        he = HawkEye(self.default_options)

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                check_dns_wildcard = he.checkDnsWildcard(invalid_type)
                self.assertIsInstance(check_dns_wildcard, bool)

    def test_check_dns_wildcard_should_return_a_boolean(self):
        he = HawkEye(self.default_options)

        check_dns_wildcard = he.checkDnsWildcard('local')
        self.assertIsInstance(check_dns_wildcard, bool)

    @unittest.skip("todo")
    def test_google_iterate(self):
        he = HawkEye(self.default_options)

        he.googleIterate(None, None)
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_bing_iterate(self):
        he = HawkEye(self.default_options)

        he.bingIterate(None, None)
        self.assertEqual('TBD', 'TBD')
