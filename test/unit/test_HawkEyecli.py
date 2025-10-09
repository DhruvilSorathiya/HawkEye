# test_hawkeyecli.py
import io
import pytest
import sys
import unittest

from hecli import HawkEyeCli


@pytest.mark.usefixtures
class TestHawkEyeCli(unittest.TestCase):
    """
    Test TestHawkEyeCli
    """

    def test_default(self):
        """
        Test default(self, line)
        """
        hecli = HawkEyeCli()

        io_output = io.StringIO()
        sys.stdout = io_output
        hecli.default("")
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertIn("Unknown command", output)

    def test_default_should_ignore_comments(self):
        """
        Test default(self, line)
        """
        hecli = HawkEyeCli()

        io_output = io.StringIO()
        sys.stdout = io_output
        result = hecli.default("# test comment")
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertEqual(None, result)
        self.assertEqual("", output)

    def test_complete_start_should_return_a_list(self):
        """
        Test complete_start(self, text, line, startidx, endidx)
        """
        hecli = HawkEyeCli()
        start = hecli.complete_start(None, None, None, None)
        self.assertIsInstance(start, list)
        self.assertEqual([], start)

    def test_complete_find_should_return_a_list(self):
        """
        Test complete_find(self, text, line, startidx, endidx)
        """
        hecli = HawkEyeCli()
        find = hecli.complete_find(None, None, None, None)
        self.assertIsInstance(find, list)
        self.assertEqual([], find)

    def test_complete_data_should_return_a_list(self):
        """
        Test complete_data(self, text, line, startidx, endidx)
        """
        hecli = HawkEyeCli()
        data = hecli.complete_data(None, None, None, None)
        self.assertIsInstance(data, list)
        self.assertEqual([], data)

    def test_complete_default(self):
        """
        Test complete_default(self, text, line, startidx, endidx)
        """
        hecli = HawkEyeCli()
        default = hecli.complete_default("", "-t -m", None, None)
        self.assertIsInstance(default, list)
        self.assertEqual('TBD', 'TBD')

        default = hecli.complete_default("", "-m -t", None, None)
        self.assertIsInstance(default, list)
        self.assertEqual('TBD', 'TBD')

    def test_complete_default_invalid_text_should_return_a_string(self):
        """
        Test complete_default(self, text, line, startidx, endidx)
        """
        hecli = HawkEyeCli()
        default = hecli.complete_default(None, "example line", None, None)
        self.assertIsInstance(default, list)
        self.assertEqual([], default)

    def test_complete_default_invalid_line_should_return_a_string(self):
        """
        Test complete_default(self, text, line, startidx, endidx)
        """
        hecli = HawkEyeCli()
        default = hecli.complete_default("example text", None, None, None)
        self.assertIsInstance(default, list)
        self.assertEqual([], default)

    def test_do_debug_should_toggle_debug(self):
        """
        Test do_debug(self, line)
        """
        hecli = HawkEyeCli(self.cli_default_options)

        hecli.do_debug(None)
        initial_debug_state = hecli.ownopts['cli.debug']
        hecli.do_debug(None)
        new_debug_state = hecli.ownopts['cli.debug']

        self.assertNotEqual(initial_debug_state, new_debug_state)

    def test_do_spool_should_toggle_spool(self):
        """
        Test do_spool(self, line)
        """
        hecli = HawkEyeCli()

        hecli.ownopts['cli.spool_file'] = '/dev/null'

        hecli.do_spool(None)
        initial_spool_state = hecli.ownopts['cli.spool']
        hecli.do_spool(None)
        new_spool_state = hecli.ownopts['cli.spool']

        self.assertNotEqual(initial_spool_state, new_spool_state)

    def test_do_history_should_toggle_history_option(self):
        """
        Test do_history(self, line)
        """
        hecli = HawkEyeCli(self.cli_default_options)

        hecli.do_history("0")
        initial_history_state = hecli.ownopts['cli.history']
        hecli.do_history("1")
        new_history_state = hecli.ownopts['cli.history']

        self.assertNotEqual(initial_history_state, new_history_state)

    def test_precmd_should_return_line(self):
        """
        Test precmd(self, line)
        """
        hecli = HawkEyeCli()
        hecli.ownopts['cli.history'] = False
        hecli.ownopts['cli.spool'] = False

        line = "example line"

        precmd = hecli.precmd(line)

        self.assertEqual(line, precmd)

    @unittest.skip("todo")
    def test_precmd_should_print_line_to_history_file(self):
        """
        Test precmd(self, line)
        """
        hecli = HawkEyeCli()
        hecli.ownopts['cli.history'] = True
        hecli.ownopts['cli.spool'] = False

        line = "example line"

        precmd = hecli.precmd(line)

        self.assertEqual(line, precmd)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_precmd_should_print_line_to_spool_file(self):
        """
        Test precmd(self, line)
        """
        hecli = HawkEyeCli()
        hecli.ownopts['cli.history'] = False
        hecli.ownopts['cli.spool'] = True
        hecli.ownopts['cli.spool_file'] = '/dev/null'

        line = "example line"

        precmd = hecli.precmd(line)

        self.assertEqual(line, precmd)

        self.assertEqual('TBD', 'TBD')

    def test_dprint_should_print_if_debug_option_is_set(self):
        """
        Test dprint(self, msg, err=False, deb=False, plain=False, color=None)
        """
        hecli = HawkEyeCli()
        hecli.ownopts['cli.debug'] = True
        hecli.ownopts['cli.spool'] = False

        io_output = io.StringIO()
        sys.stdout = io_output
        hecli.dprint("example output")
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertIn("example output", output)

    def test_dprint_should_not_print_unless_debug_option_is_set(self):
        """
        Test dprint(self, msg, err=False, deb=False, plain=False, color=None)
        """
        hecli = HawkEyeCli()
        hecli.ownopts['cli.debug'] = False
        hecli.ownopts['cli.spool'] = False

        io_output = io.StringIO()
        sys.stdout = io_output
        hecli.dprint("example output")
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertIn("", output)

    def test_ddprint_should_print_if_debug_option_is_set(self):
        """
        Test ddprint(self, msg)
        """
        hecli = HawkEyeCli()
        hecli.ownopts['cli.debug'] = True
        hecli.ownopts['cli.spool'] = False

        io_output = io.StringIO()
        sys.stdout = io_output
        hecli.ddprint("example debug output")
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertIn("example debug output", output)

    def test_ddprint_should_not_print_unless_debug_option_is_set(self):
        """
        Test ddprint(self, msg)
        """
        hecli = HawkEyeCli()
        hecli.ownopts['cli.debug'] = False
        hecli.ownopts['cli.spool'] = False

        io_output = io.StringIO()
        sys.stdout = io_output
        hecli.ddprint("example debug output")
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertEqual("", output)

    def test_edprint_should_print_error_regardless_of_debug_option(self):
        """
        Test edprint(self, msg)
        """
        hecli = HawkEyeCli()
        hecli.ownopts['cli.debug'] = False
        hecli.ownopts['cli.spool'] = False

        io_output = io.StringIO()
        sys.stdout = io_output
        hecli.edprint("example debug output")
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertIn("example debug output", output)

    def test_pretty_should_return_a_string(self):
        """
        Test pretty(self, data, titlemap=None)
        """
        hecli = HawkEyeCli()

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                pretty = hecli.pretty(invalid_type)
                self.assertEqual("", pretty)

    def test_request_invalid_url_should_return_none(self):
        """
        Test request(self, url, post=None)
        """
        hecli = HawkEyeCli()

        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                result = hecli.request(invalid_type)
                self.assertEqual(None, result)

    def test_emptyline_should_return_none(self):
        """
        Test emptyline(self)
        """
        hecli = HawkEyeCli()
        emptyline = hecli.emptyline()
        self.assertEqual(None, emptyline)

    def test_completedefault_should_return_empty_list(self):
        """
        Test completedefault(self, text, line, begidx, endidx)
        """
        hecli = HawkEyeCli()
        completedefault = hecli.completedefault(None, None, None, None)
        self.assertIsInstance(completedefault, list)
        self.assertEqual([], completedefault)

    def test_myparseline_should_return_a_list_of_two_lists(self):
        """
        Test myparseline(self, cmdline, replace=True)
        """
        hecli = HawkEyeCli()
        parsed_line = hecli.myparseline(None)

        self.assertEqual(len(parsed_line), 2)
        self.assertIsInstance(parsed_line, list)
        self.assertIsInstance(parsed_line[0], list)
        self.assertIsInstance(parsed_line[1], list)

        parsed_line = hecli.myparseline("")

        self.assertEqual(len(parsed_line), 2)
        self.assertIsInstance(parsed_line, list)
        self.assertIsInstance(parsed_line[0], list)
        self.assertIsInstance(parsed_line[1], list)

    def test_send_output(self):
        """
        Test send_output(self, data, cmd, titles=None, total=True, raw=False)
        """
        hecli = HawkEyeCli()

        io_output = io.StringIO()
        sys.stdout = io_output
        hecli.send_output("{}", "", raw=True)
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertIn("Total records: 0", output)

        self.assertEqual('TBD', 'TBD')

    def test_do_query(self):
        """
        Test do_query(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_query(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_ping(self):
        """
        Test do_ping(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_ping(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_modules(self):
        """
        Test do_modules(self, line, cacheonly=False)
        """
        hecli = HawkEyeCli()
        hecli.do_modules(None, None)

        self.assertEqual('TBD', 'TBD')

    def test_do_types(self):
        """
        Test do_types(self, line, cacheonly=False)
        """
        hecli = HawkEyeCli()
        hecli.do_types(None, None)

        self.assertEqual('TBD', 'TBD')

    def test_do_load(self):
        """
        Test do_load(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_load(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_scaninfo(self):
        """
        Test do_scaninfo(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_scaninfo(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_scans(self):
        """
        Test do_scans(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_scans(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_data(self):
        """
        Test do_data(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_data(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_export(self):
        """
        Test do_export(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_export(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_logs(self):
        """
        Test do_logs(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_logs(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_start(self):
        """
        Test do_start(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_start(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_stop(self):
        """
        Test do_stop(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_stop(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_search(self):
        """
        Test do_search(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_search(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_find(self):
        """
        Test do_find(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_find(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_summary(self):
        """
        Test do_summary(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_summary(None)

        self.assertEqual('TBD', 'TBD')

    def test_do_delete(self):
        """
        Test do_delete(self, line)
        """
        hecli = HawkEyeCli()
        hecli.do_delete(None)

        self.assertEqual('TBD', 'TBD')

    def test_print_topic(self):
        """
        Test print_topics(self, header, cmds, cmdlen, maxcol)
        """
        hecli = HawkEyeCli()

        io_output = io.StringIO()
        sys.stdout = io_output
        hecli.print_topics(None, "help", None, None)
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertIn("Command", output)
        self.assertIn("Description", output)

        self.assertEqual('TBD', 'TBD')

    def test_do_set_should_set_option(self):
        """
        Test do_set(self, line)
        """
        hecli = HawkEyeCli()
        hecli.ownopts['cli.test_opt'] = None

        hecli.do_set('cli.test_opt = "test value"')
        new_test_opt = hecli.ownopts['cli.test_opt']

        self.assertEqual(new_test_opt, 'test value')

    def test_do_shell(self):
        """
        Test do_shell(self, line)
        """
        hecli = HawkEyeCli()

        io_output = io.StringIO()
        sys.stdout = io_output
        hecli.do_shell("")
        sys.stdout = sys.__stdout__
        output = io_output.getvalue()

        self.assertIn("Running shell command:", output)

    def test_do_clear(self):
        """
        Test do_clear(self, line)
        """
        hecli = HawkEyeCli()

        io_output = io.StringIO()
        sys.stderr = io_output
        hecli.do_clear(None)
        sys.stderr = sys.__stderr__
        output = io_output.getvalue()

        self.assertEqual("\x1b[2J\x1b[H", output)

    def test_do_exit(self):
        """
        Test do_exit(self, line)
        """
        hecli = HawkEyeCli()
        do_exit = hecli.do_exit(None)
        self.assertTrue(do_exit)

    def test_do_eof(self):
        """
        Test do_EOF(self, line)
        """
        hecli = HawkEyeCli()
        do_eof = hecli.do_EOF(None)
        self.assertTrue(do_eof)
