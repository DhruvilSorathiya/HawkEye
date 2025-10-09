# test_he.py
import subprocess
import sys
import unittest


class TestSf(unittest.TestCase):
    """
    Test TestSf
    """

    default_types = [
        ""
    ]

    default_modules = [
        "hep_base64",
        "hep_bitcoin",
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
        "hep_strangeheaders",
        "hep_webframework",
        "hep_webserver",
        "hep_webanalytics",
    ]

    def execute(self, command):
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, err = proc.communicate()
        return out, err, proc.returncode

    def test_no_args_should_print_arg_l_required(self):
        out, err, code = self.execute([sys.executable, "he.py"])
        self.assertIn(b"HawkEye requires -l <ip>:<port> to start the web server. Try --help for guidance.", out)
        self.assertEqual(b"", err)
        self.assertEqual(255, code)

    def test_help_arg_should_print_help_and_exit(self):
        out, err, code = self.execute([sys.executable, "he.py", "-h"])
        self.assertIn(b"show this help message and exit", out)
        self.assertEqual(b"", err)
        self.assertEqual(0, code)

    def test_modules_arg_should_print_modules_and_exit(self):
        out, err, code = self.execute([sys.executable, "he.py", "-M"])
        self.assertIn(b"Modules available:", err)
        self.assertEqual(0, code)

    def test_types_arg_should_print_types_and_exit(self):
        out, err, code = self.execute([sys.executable, "he.py", "-T"])
        self.assertIn(b"Types available:", err)
        self.assertEqual(0, code)

    @unittest.skip("todo")
    def test_l_arg_should_start_web_server(self):
        listen = "127.0.0.1:5001"
        out, err, code = self.execute([sys.executable, "he.py", "-l", listen])
        self.assertIn(bytes(f"Starting web server at {listen}", 'utf-8'), err)
        self.assertEqual(0, code)

    def test_debug_arg_should_enable_and_print_debug_output(self):
        out, err, code = self.execute([sys.executable, "he.py", "-d", "-m", "example module", "-s", "hawkeye.net"])
        self.assertIn(b"[DEBUG]", err)
        self.assertIn(b"hep__stor_db : Storing an event: ROOT", err)
        self.assertEqual(0, code)

    def test_quiet_arg_should_hide_debug_output(self):
        out, err, code = self.execute([sys.executable, "he.py", "-q", "-m", "example module", "-s", "hawkeye.net"])
        self.assertNotIn(b"[INFO]", err)
        self.assertEqual(0, code)

    def test_run_scan_invalid_target_should_exit(self):
        invalid_target = '.'
        out, err, code = self.execute([sys.executable, "he.py", "-s", invalid_target])
        self.assertIn(bytes(f"Could not determine target type. Invalid target: {invalid_target}", 'utf-8'), err)
        self.assertEqual(255, code)

    def test_run_scan_with_modules_no_target_should_exit(self):
        out, err, code = self.execute([sys.executable, "he.py", "-m", ",".join(self.default_modules)])
        self.assertIn(b"You must specify a target when running in scan mode", err)
        self.assertEqual(255, code)

    def test_run_scan_with_types_no_target_should_exit(self):
        out, err, code = self.execute([sys.executable, "he.py", "-t", ",".join(self.default_types)])
        self.assertIn(b"You must specify a target when running in scan mode", err)
        self.assertEqual(255, code)

    def test_run_scan_with_invalid_module_should_run_scan_and_exit(self):
        module = "invalid module"
        out, err, code = self.execute([sys.executable, "he.py", "-m", module, "-s", "hawkeye.net"])
        self.assertIn(bytes(f"Failed to load module: {module}", 'utf-8'), err)
        self.assertEqual(0, code)

    def test_run_scan_with_invalid_type_should_exit(self):
        out, err, code = self.execute([sys.executable, "he.py", "-t", "invalid type", "-s", "hawkeye.net"])
        self.assertIn(b"Based on your criteria, no modules were enabled", err)
        self.assertEqual(255, code)

    def test_run_scan_should_run_scan_and_exit(self):
        target = "hawkeye.net"
        out, err, code = self.execute([sys.executable, "he.py", "-m", ",".join(self.default_modules), "-s", target])
        self.assertIn(b"Scan completed with status FINISHED", err)
        self.assertEqual(0, code)

        for module in self.default_modules:
            with self.subTest(module=module):
                self.assertIn(module.encode(), err)

    @unittest.skip("output buffering sometimes causes this test to fail")
    def test_run_scan_should_print_scan_result_and_exit(self):
        target = "hawkeye.net"
        out, err, code = self.execute([sys.executable, "he.py", "-m", ",".join(self.default_modules), "-s", target, "-o", "csv"])
        self.assertIn(b"Scan completed with status FINISHED", err)
        self.assertEqual(0, code)

        for module in self.default_modules:
            with self.subTest(module=module):
                self.assertIn(module.encode(), err)

        expected_output = [
            "Source,Type,Data",
            "HawkEye UI,Internet Name,hawkeye.net,hawkeye.net\n",
            "HawkEye UI,Domain Name,hawkeye.net,hawkeye.net\n",
            "hep_countryname,Country Name,hawkeye.net,United States\n",
        ]
        for output in expected_output:
            self.assertIn(bytes(output, 'utf-8'), out)
