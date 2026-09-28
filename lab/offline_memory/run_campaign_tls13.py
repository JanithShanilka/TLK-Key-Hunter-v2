#!/usr/bin/env python3
"""Bounded, sequential TLS 1.3 lab campaign with compact retention."""
import argparse
import csv
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

GIB = 1024 ** 3
SCRIPTS = ('capture_firefox.py', 'extended_server.py', 'core_memory.py', 'rank_core.py',
           'rank_tls13.py', 'tls13_packets.py', 'check_tls13_scenario.py',
           'validate_tls13.py', 'verify_tls13.py')


def utc():
    return datetime.now(timezone.utc).isoformat()


def save(path, data):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def allocated(root):
    return sum(p.stat().st_blocks * 512 for p in root.rglob('*') if p.is_file() and not p.is_symlink())


def storage_ok(used, free, budget, reserve, allowance):
    return used + allowance <= budget and free >= reserve


def aggregate(rows):
    successes = sum(bool(row.get('complete_offline_recovery')) for row in rows)
    return {'attempted': len(rows), 'successful': successes,
            'unsuccessful': len(rows) - successes,
            'observed_success_fraction': successes / len(rows) if rows else None}


def run_stage(command, log, timeout, guard):
    with log.open('w') as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT)
        started = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    raise RuntimeError('stage_timeout')
                if not guard():
                    raise RuntimeError('storage_limit')
                time.sleep(1)
            if process.returncode:
                raise RuntimeError('stage_exit_' + str(process.returncode))
        except BaseException:
            # capture_firefox handles SIGTERM and cleans up owned browser/server groups.
            process.terminate()
            try:
                process.wait(timeout=40)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--campaign-id', required=True)
    parser.add_argument('--scenario', required=True,
                        choices=('before-response', 'delayed', 'resumption', 'keyupdate', 'concurrency'))
    parser.add_argument('--count', type=int, default=10)
    parser.add_argument('--interval-seconds', type=int, default=300, help='Minimum start-to-start spacing; never overlaps')
    parser.add_argument('--start-delay-seconds', type=int, default=0)
    parser.add_argument('--budget-gib', type=float, default=8, help='Allocated budget across ALL pilot cases')
    parser.add_argument('--minimum-free-gib', type=float, default=20)
    parser.add_argument('--capture-python', default='/home/researcher/.venv/bin/python')
    parser.add_argument('--lab-disable-socket-sandbox', action='store_true')
    parser.add_argument('--lab-accept-insecure-certs', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run only as root on the authorized controlled lab host')
    if not 1 <= args.count <= 100 or args.interval_seconds < 600 or args.budget_gib <= 0 or args.minimum_free_gib < 20:
        parser.error('Require 1–100 cases, spacing >=600 seconds, positive budget, and >=20 GiB free reserve')
    if not args.campaign_id or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in args.campaign_id):
        parser.error('Campaign ID must contain only letters, numbers, hyphens or underscores')
    os.umask(0o077)
    workspace = args.workspace.resolve()
    cases = workspace / 'cases'
    cases.mkdir(exist_ok=True)
    lock = (workspace / 'campaign.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    batch = workspace / 'campaigns' / args.campaign_id
    batch.mkdir(parents=True, exist_ok=False)
    # Researchers need traversal to immutable script snapshots, not reference access.
    batch.parent.chmod(0o755)
    batch.chmod(0o755)
    snapshot = batch / 'tools'
    snapshot.mkdir(mode=0o755)
    snapshot.chmod(0o755)  # Explicitly override restrictive process umask for researcher traversal.
    hashes = {}
    for name in SCRIPTS:
        source = Path(__file__).parent / name
        target = snapshot / name
        shutil.copyfile(source, target)
        target.chmod(0o444)
        hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    shutil.copyfile(Path(__file__), batch / 'runner.py')
    hashes['run_campaign_tls13.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    settings = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    save(batch / 'manifest.json', {'started': utc(), 'settings': settings, 'script_sha256': hashes,
        'retention': 'After verification and durable result save, delete raw core, disposable profile and runtime. Keep compact evidence. Interrupted/setup failures stop for inspection.', 'protocol': 'TLS1.3',
        'scenario': args.scenario,
        'design': 'Scenario condition check, reference-blind fixed CKA_VALUE candidate enumeration, direct per-flow/per-generation TLS-record authentication, then independent reference equality, marker, and wrong-secret verification.'})
    rows = []
    state = {'state': 'running', 'started': utc(), 'campaign_id': args.campaign_id, 'planned': args.count}
    budget = int(args.budget_gib * GIB)
    reserve = int(args.minimum_free_gib * GIB)
    allowance = GIB

    def publish():
        save(batch / 'summary.json', {**state, **aggregate(rows), 'updated': utc(), 'allocated_case_bytes': allocated(cases)})
        save(batch / 'runs.json', rows)
        columns = ['case_id','scenario','started','ended','status','failure_class','failed_stage',
                   'condition_ok','candidate_count','target_count','all_target_pass_counts_one',
                   'assignment_unique','exact_match_all_targets','controlled_markers_all_targets',
                   'wrong_secret_controls_all_pass','complete_offline_recovery','elapsed_seconds',
                   'dump_apparent_bytes','dump_allocated_bytes']
        temp = batch / 'runs.csv.tmp'
        with temp.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)
        temp.replace(batch / 'runs.csv')

    publish()
    delay_end = time.monotonic() + max(0, args.start_delay_seconds)
    while time.monotonic() < delay_end and not (batch / 'STOP').exists():
        time.sleep(1)
    for number in range(1, args.count + 1):
        if (batch / 'STOP').exists():
            state['state'] = 'stopped_by_request'
            break
        if not storage_ok(allocated(cases), shutil.disk_usage(workspace).free, budget, reserve, allowance):
            state['state'] = 'stopped_storage_limit'
            break
        started = time.monotonic()
        case_id = args.campaign_id + '-' + str(number).zfill(3)
        case = cases / case_id
        reference = Path('/root/tlkh-memory-reference') / case_id
        row = {'case_id': case_id, 'scenario': args.scenario, 'started': utc(),
               'status': 'running', 'complete_offline_recovery': False}
        rows.append(row)
        state['current_case'] = case_id
        publish()
        capture = [args.capture_python, str(snapshot / 'capture_firefox.py'), '--case', str(case),
                   '--reference', str(reference), '--tls-version', '1.3', '--scenario', args.scenario]
        for flag in ('lab_disable_socket_sandbox', 'lab_accept_insecure_certs'):
            if getattr(args, flag):
                capture.append('--' + flag.replace('_', '-'))
        researcher = ['runuser', '-u', 'researcher', '--', sys.executable]
        stages = [
            ('capture', capture, 240),
            ('reference_isolation', ['runuser','-u','researcher','--','test','!','-r', str(reference / 'server-reference.keys')], 10),
            ('condition', researcher + [str(snapshot / 'check_tls13_scenario.py'), '--case', str(case),
                                        '--output', str(case / 'scenario-condition.json')], 60),
            ('rank', researcher + [str(snapshot / 'rank_tls13.py'), '--core', str(case / 'firefox.core'), '--output', str(case / 'offline-tls13')], 180),
            ('packet_validation', researcher + [str(snapshot / 'validate_tls13.py'), '--case', str(case),
                '--offline', str(case / 'offline-tls13'), '--output', str(case / 'offline-tls13-pcap')], 300),
            ('verify', [sys.executable, str(snapshot / 'verify_tls13.py'), '--case', str(case), '--reference', str(reference / 'server-reference.keys')], 180)]
        for name, command, timeout in stages:
            try:
                run_stage(command, batch / (case_id + '-' + name + '.log'), timeout,
                          lambda: allocated(cases) <= budget and shutil.disk_usage(workspace).free >= reserve)
                if name == 'condition':
                    condition = json.loads((case / 'scenario-condition.json').read_text())
                    row['condition_ok'] = condition['condition_ok']
                    row['target_count'] = len(condition['targets'])
                elif name == 'rank':
                    memory = json.loads((case / 'offline-tls13/selection-seal.json').read_text())
                    row['candidate_count'] = memory['candidate_count']
                elif name == 'packet_validation':
                    sealed = json.loads((case / 'offline-tls13-pcap/selection-seal.json').read_text())
                    row['all_target_pass_counts_one'] = all(value == 1 for value in sealed['target_pass_counts'].values())
                    row['assignment_unique'] = sealed['assignment_unique']
                elif name == 'verify':
                    result = json.loads((case / 'verification-tls13/summary.json').read_text())
                    for field in ('exact_match_all_targets', 'controlled_markers_all_targets',
                                  'wrong_secret_controls_all_pass', 'complete_offline_recovery'):
                        row[field] = result[field]
                    row['status'] = 'success' if result['complete_offline_recovery'] else 'recovery_failed'
            except Exception as error:
                failure_class = ('setup' if name in ('capture', 'reference_isolation') else
                                 'condition' if name == 'condition' else
                                 'extraction' if name in ('rank', 'packet_validation') else 'verification')
                row.update({'status': 'failed', 'failure_class': failure_class,
                            'failed_stage': name, 'error': str(error)})
                break
        dump = case / 'firefox.core'
        if dump.exists():
            info = dump.stat()
            row.update({'dump_apparent_bytes': info.st_size, 'dump_allocated_bytes': info.st_blocks * 512})
            allowance = max(allowance, info.st_blocks * 512 * 2)
        row.update({'ended': utc(), 'elapsed_seconds': time.monotonic() - started})
        save(batch / (case_id + '-result.json'), row)
        publish()
        if row['status'] in ('success', 'recovery_failed'):
            # Verification has hashed the core and result is durable before removal.
            if case.is_symlink() or case.parent != cases:
                raise RuntimeError('Unexpected case path during retention cleanup')
            if dump.exists():
                dump.unlink()
            for name in ('profile', 'runtime'):
                disposable = case / name
                if disposable.is_symlink():
                    raise RuntimeError('Unexpected disposable-directory symlink')
                if disposable.exists():
                    shutil.rmtree(disposable)
            row['raw_dump_deleted'] = True
            row['disposable_profile_deleted'] = True
            row['cleanup_completed'] = utc()
            save(batch / (case_id + '-result.json'), row)
            publish()
        # Setup/tool failure may leave stale processes; stop rather than risk overlapping acquisition.
        if row['status'] == 'failed':
            state['state'] = 'stopped_stage_failure'
            break
        if number < args.count:
            while time.monotonic() - started < args.interval_seconds:
                if (batch / 'STOP').exists():
                    break
                time.sleep(1)
    else:
        state['state'] = 'completed'
    state['ended'] = utc()
    publish()
    print(json.dumps({**state, **aggregate(rows)}))


if __name__ == '__main__':
    main()
