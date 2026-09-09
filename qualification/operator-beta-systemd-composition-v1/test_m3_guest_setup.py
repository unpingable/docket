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


if __name__ == '__main__':
    unittest.main()
