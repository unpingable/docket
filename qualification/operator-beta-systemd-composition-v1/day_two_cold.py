"""Cold-cohort extension using the existing disposable VM producer only."""
import hashlib
import json
import pathlib
import shlex
import shutil

OLD_RUN = pathlib.Path('/data/git/.campaign-artifacts/constellation-operator-beta-composed-m2-run-002')
OLD_PACKAGE_SHA = '0fd1ce9e1be48b56ba5e526993a94c4682499bb9dbd9304dffd4500c01603636'
OLD_STORE_SHA = 'e6a442e199449093c105b85f1882a31b2ea64cf70d61b7f1a72e7635bdb7e153'


def exercise(producer, nq, control):
    here = pathlib.Path(__file__).resolve().parent
    producer.state('cold_cohort_prepare', 'qualify exact old/new packages in separate stopped cohorts')
    inputs = producer.output / 'input'
    for source, name, expected in (
        (OLD_RUN / 'input/nq-ng_amd64.deb', 'm4-old-nq.deb', OLD_PACKAGE_SHA),
        (OLD_RUN / 'evidence/control-nq-backup.sqlite', 'm4-old-store.sqlite', OLD_STORE_SHA),
    ):
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise nq.Refusal('cold-cohort historical input digest mismatch')
        destination = inputs / name
        if destination.exists():
            raise nq.Refusal('cold-cohort input destination already exists')
        shutil.copyfile(source, destination)
        destination.chmod(0o400)
        producer.scp_to(control, [destination], '/home/betaoperator/' + name)
    producer.scp_to(control, [here / 'day_two_cold_guest.py', here / 'day_two_restore.py'], '/home/betaoperator/')
    producer.ssh(control, 'sudo install -d -o root -g root -m 0755 /usr/local/libexec/constellation-m4-cold; '
                 'sudo install -o root -g root -m 0444 /home/betaoperator/day_two_cold_guest.py /home/betaoperator/day_two_restore.py /usr/local/libexec/constellation-m4-cold/')
    prefix = 'sudo python3 -B /usr/local/libexec/constellation-m4-cold/day_two_cold_guest.py '

    def step(name, expected=0):
        producer.state('cold_cohort_' + name, 'execute one explicit step; no automatic retry')
        result = producer.ssh(control, prefix + shlex.quote(name), check=False)
        if result.returncode != expected:
            raise nq.Refusal(f'cold-cohort {name}: expected {expected}, observed {result.returncode}')

    try:
        step('prepare', 23)
        step('inspect')
        step('cut-one', 23)
        step('inspect')
        step('rollback')
        step('cut-two', 23)
        step('inspect')
        # Reuse the owner's exact capability-bounded helper launcher. Only the
        # config path changes to the explicitly initialized current cohort.
        for arguments, filename in (
            (['watcher', 'admit', 'http-restart'], 'cold-fresh-admission.json'),
            (['diagnostics', 'execute', 'http-restart'], 'cold-fresh-diagnostic.json'),
        ):
            command = nq.nq_helper_command(arguments).replace('--config=/etc/nq/operator-beta.toml', '--config=/etc/nq/nq.toml')
            result = producer.ssh(control, command)
            nq.atomic_write(producer.output / 'evidence' / filename, result.stdout, 0o400)
            decoded = json.loads(result.stdout)
            if not isinstance(decoded, dict):
                raise nq.Refusal('fresh owner command did not return a structured record')
            if filename == 'cold-fresh-diagnostic.json':
                nq.verify_diagnostic_artifact(
                    decoded, profile='nq.http_endpoint', condition='unresolved',
                    instance='http-restart',
                    bindings=json.loads((producer.output / 'evidence/bindings.json').read_bytes()),
                )
        step('post-cut', 23)
        step('inspect')
        step('finish')
        result = producer.ssh(control, 'sudo cat /var/lib/nq/m4-cold/RESULT.json').stdout
        if json.loads(result)['disposition'] != 'COLD_COHORT_VM_DEMONSTRATED':
            raise nq.Refusal('cold-cohort final procedure result absent')
        nq.atomic_write(producer.output / 'evidence/cold-cohort-result.json', result, 0o400)
    except BaseException:
        # Preserve bounded checkpoint evidence before producer scope teardown.
        producer.ssh(control, 'sudo cat /var/lib/nq/m4-cold/CHECKPOINT.json; '
                     'sudo journalctl --no-pager -u nqd.service -n 100', check=False)
        raise
    producer.ssh(control, 'sudo tar -C /var/lib/nq/m4-cold -cf /home/betaoperator/m4-cold.tar .; '
                 'sudo chown betaoperator:betaoperator /home/betaoperator/m4-cold.tar; chmod 0400 /home/betaoperator/m4-cold.tar')
    archive = producer.output / 'evidence/cold-cohort-private.tar'
    producer.scp_from(control, '/home/betaoperator/m4-cold.tar', archive)
    archive.chmod(0o400)
    if archive.stat().st_size > 512 * 1024 * 1024:
        raise nq.Refusal('cold-cohort archive exceeds fixture evidence bound')
    producer.ssh(control, 'sudo test ! -e /etc/nq/nq.toml; '
                 'sudo rm -rf /var/lib/nq/m4-cold /usr/local/libexec/constellation-m4-cold; '
                 'rm -f /home/betaoperator/m4-cold.tar /home/betaoperator/m4-old-nq.deb /home/betaoperator/m4-old-store.sqlite /home/betaoperator/day_two_cold_guest.py /home/betaoperator/day_two_restore.py')
    producer.complete_phase('cold_cohort_proved', 'existing scoped composition teardown')
