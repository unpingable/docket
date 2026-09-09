import unittest
import m3_guest_setup


class GuestSetupTests(unittest.TestCase):
    def test_writer_roles_keep_fixed_no_retry_and_no_external_acquisition(self):
        main = m3_guest_setup.writer_unit('main')
        discovery = m3_guest_setup.writer_unit('discovery')
        for unit in (main, discovery):
            self.assertIn('Restart=no\n', unit)
            self.assertIn('JETSTREAM_URL=ws://127.0.0.1:9\n', unit)
            self.assertIn('--db /var/lib/constellation-m3/run/source.sqlite ', unit)
            self.assertNotIn('ExecStartPre=', unit)
        self.assertIn('run --ingest-interval 0 --scan-interval 0\n', main)
        self.assertIn('discover-stream --backstop-interval 0\n', discovery)

    def test_unknown_writer_is_not_a_command_interpolation_surface(self):
        with self.assertRaises(ValueError):
            m3_guest_setup.writer_unit('main\nExecStart=/bin/false')

    def test_per_case_paths_are_explicit_and_bounded(self):
        text = m3_guest_setup.writer_unit('main', '/var/lib/constellation-m3/cases/one/operation')
        self.assertIn('/cases/one/operation/source.sqlite', text)
        for target in ('/tmp/other', '/var/lib/constellation-m3', '/var/lib/constellation-m3/one\nExecStart=other'):
            with self.assertRaises(ValueError):
                m3_guest_setup.writer_unit('main', target)

    def test_failed_start_is_actual_cli_refusal_without_retry(self):
        text = m3_guest_setup.writer_unit('main', failing_start=True)
        self.assertIn('-m labelwatch.cli ', text)
        self.assertIn('--scan-interval invalid-fixture-number\n', text)
        self.assertIn('Restart=no\n', text)
        with self.assertRaises(ValueError):
            m3_guest_setup.writer_unit('discovery', failing_start=True)


if __name__ == '__main__':
    unittest.main()
