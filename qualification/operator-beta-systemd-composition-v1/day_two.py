"""Bounded extension of the existing disposable composition VM procedure."""
import json
import pathlib


def exercise(producer, nq, guests):
    here = pathlib.Path(__file__).resolve().parent
    for guest in guests:
        producer.state('day_two_' + guest.role, 'execute fixed packaged-owner maintenance; retain guest on failure')
        producer.scp_to(guest, [here / 'day_two_guest.py', here / 'day_two_restore.py'], '/home/betaoperator/')
        producer.ssh(guest, "sudo install -d -o root -g root -m 0755 /usr/local/libexec/constellation-m4; "
                     "sudo install -o root -g root -m 0444 /home/betaoperator/day_two_guest.py /home/betaoperator/day_two_restore.py /usr/local/libexec/constellation-m4/; "
                     "sudo python3 -B /usr/local/libexec/constellation-m4/day_two_guest.py")
        result = producer.ssh(guest, 'sudo cat /var/lib/nq/m4-day-two/RESULT.json').stdout
        decoded = json.loads(result)
        if decoded.get('disposition') != 'DAY_TWO_PROCEDURE_DEMONSTRATED':
            raise nq.Refusal('day-two procedure did not establish its declared result')
        nq.atomic_write(producer.output / 'evidence' / (guest.role + '-m4-day-two.json'), result, 0o400)
        producer.ssh(guest, 'sudo tar -C /var/lib/nq/m4-day-two -cf /home/betaoperator/m4-day-two.tar .; '
                     'sudo chown betaoperator:betaoperator /home/betaoperator/m4-day-two.tar; '
                     'chmod 0400 /home/betaoperator/m4-day-two.tar')
        archive = producer.output / 'evidence' / (guest.role + '-m4-private-evidence.tar')
        producer.scp_from(guest, '/home/betaoperator/m4-day-two.tar', archive)
        archive.chmod(0o400)
        if archive.stat().st_size > 128 * 1024 * 1024:
            raise nq.Refusal('day-two evidence archive exceeds bound; retain guest for inspection')
        # Only these newly enrolled fixture paths; accepted stores and prior
        # run evidence are not deletion targets. Base teardown remains owner.
        producer.ssh(guest, 'sudo rm -rf /var/lib/nq/m4-day-two /usr/local/libexec/constellation-m4; '
                     'rm -f /home/betaoperator/m4-day-two.tar /home/betaoperator/day_two_guest.py /home/betaoperator/day_two_restore.py; '
                     'sudo test ! -e /etc/nq/nq.toml; sudo test ! -e /var/lib/nq/m4-day-two; '
                     'test "$(systemctl show nqd.service --property=ActiveState --value)" = inactive')
    producer.complete_phase('day_two_proved', 'existing composition teardown')
