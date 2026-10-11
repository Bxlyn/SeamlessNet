#!/usr/bin/env python3
"""SeamlessNet automated Docker comparison runner. Python 3.9+, no dependencies."""
import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
import time

A = '172.20.0.30'
B = '172.21.0.30'
A_SRC = '172.20.0.20'
QUIC_A = '172.20.0.10'
PORT = '5201'


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds')


def run(args, timeout=30, check=True, output=None):
    try:
        p = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=timeout)
    except subprocess.TimeoutExpired as e:
        if output is not None:
            pathlib.Path(output).write_text(f'TIMEOUT after {timeout}s\n{e.stdout or ""}\n{e.stderr or ""}', encoding='utf-8')
        raise RuntimeError(f'Command timed out ({timeout}s): {args}') from e
    if output is not None:
        pathlib.Path(output).write_text(p.stdout + ('\nSTDERR:\n' + p.stderr if p.stderr else ''), encoding='utf-8')
    if check and p.returncode:
        raise RuntimeError(f'Exit {p.returncode}: {args}\n{p.stderr[-700:]}')
    return p


def dc(*args, timeout=90, check=True, output=None):
    return run(['docker', 'compose', *args], timeout=timeout, check=check, output=output)


def client(*args, timeout=90, check=True, output=None):
    return run(['docker', 'exec', 'seamlessnet-client', *args], timeout=timeout, check=check, output=output)


def state(service):
    name = {'client': 'seamlessnet-client', 'server': 'seamlessnet-server'}[service]
    p = run(['docker', 'inspect', '-f', '{{.State.Status}}', name],
            timeout=60, check=False)
    return p.stdout.strip() if p.returncode == 0 else 'missing'


def alive():
    if state('client') != 'running':
        raise RuntimeError('Client not running; check docker compose logs client')


def wait_ready(timeout=65):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if state('client') == 'running':
            link = client('ip', 'link', 'show', 'tun0', check=False)
            logs = dc('logs', '--tail=90', 'client', timeout=15).stdout
            if link.returncode == 0 and '[CONNECTION] QUIC ready' in logs:
                if '[CONNECTION] closed' in logs:
                    raise RuntimeError('QUIC closed immediately after connecting')
                return
        time.sleep(1)
    raise RuntimeError('Client not ready within 65 seconds')


def reset_quic():
    print('  Resetting server and client...', flush=True)
    dc('stop', 'client', timeout=30, check=False)
    dc('up', '-d', '--force-recreate', 'server', timeout=90)
    dc('up', '-d', '--force-recreate', 'client', timeout=90)
    wait_ready()
    set_mode('quic')
    p = client('ping', '-c', '2', '-W', '2', A, timeout=12, check=False)
    if p.returncode:
        raise RuntimeError('QUIC readiness ping failed: ' + p.stdout[-300:])


def clear_direct():
    # Delete only our exact OUTPUT rule, not arbitrary firewall rules.
    spec = ['-s', A_SRC, '-d', A, '-j', 'DROP']
    for _ in range(5):
        p = client('iptables', '-C', 'OUTPUT', *spec, check=False)
        if p.returncode:
            break
        client('iptables', '-D', 'OUTPUT', *spec)


def clear_quic():
    client('sh', 'scripts/blackhole-a.sh', 'off', check=False)


def set_mode(mode):
    alive()
    clear_direct()
    clear_quic()
    if mode == 'direct':
        client('ip', 'route', 'del', A + '/32', check=False)
    else:
        client('ip', 'route', 'replace', A + '/32', 'dev', 'tun0', 'advmss', '900')
    route = client('ip', 'route', 'get', A).stdout
    if mode == 'direct' and ('dev tun0' in route or 'src ' + A_SRC not in route):
        raise RuntimeError('Direct route invalid: ' + route)
    if mode == 'quic' and 'dev tun0' not in route:
        raise RuntimeError('QUIC route invalid: ' + route)
    return route


def failure(mode, on):
    if mode == 'direct':
        spec = ['-s', A_SRC, '-d', A, '-j', 'DROP']
        if on:
            clear_direct()
            client('iptables', '-I', 'OUTPUT', '1', *spec)
        else:
            clear_direct()
    else:
        client('sh', 'scripts/blackhole-a.sh', 'on' if on else 'off')


def test_cmd(proto):
    if proto == 'icmp':
        # Inside-container hard deadline independent of received packet count.
        return ['timeout', '-s', 'INT', '-k', '3', '50', 'ping', '-D', '-i', '0.05', '-w', '45', A]
    if proto == 'tcp':
        return ['timeout', '-s', 'INT', '-k', '5', '75', 'iperf3', '-c', A, '-p', PORT, '-t', '60', '-i', '1', '-M', '900', '--get-server-output']
    return ['timeout', '-s', 'INT', '-k', '5', '75', 'iperf3', '-c', A, '-p', PORT, '-u', '-b', '20M', '-l', '800', '-t', '60', '-i', '1', '--get-server-output']


def trial(root, mode, proto, n):
    folder = root / f'{mode}-{proto}' / f'run-{n:02d}'
    folder.mkdir(parents=True, exist_ok=True)
    meta = {'mode': mode, 'protocol': proto, 'run': n, 'events': [], 'valid': False}
    print(f'\n[{stamp()}] {mode.upper()} {proto.upper()} run {n}', flush=True)
    proc = None
    injected = False
    start_log = stamp()
    try:
        if mode == 'quic':
            reset_quic()
        else:
            set_mode('direct')
        route = client('ip', 'route', 'get', A).stdout
        (folder / 'route.txt').write_text(route, encoding='utf-8')
        run(['docker', 'inspect', '-f', '{{.Name}} {{.State.Status}}', 'seamlessnet-client', 'seamlessnet-server', 'seamlessnet-web'], timeout=60, output=folder / 'containers.txt')
        dc('logs', '--tail=40', 'client', output=folder / 'startup-logs.txt')
        # Start the *Docker CLI* in a subprocess, with stdout redirected to disk.
        # Never background docker compose exec in Git Bash, and never wait indefinitely.
        cmd = ['docker', 'exec', 'seamlessnet-client', *test_cmd(proto)]
        out = (folder / 'traffic.txt').open('w', encoding='utf-8')
        proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, text=True)
        begin = time.monotonic()
        meta['events'].append({'event': 'traffic_started', 'time': stamp()})
        time.sleep(10)
        if proc.poll() is not None:
            raise RuntimeError('Traffic command ended before failure; inspect traffic.txt')
        alive()
        failure(mode, True)
        injected = True
        meta['events'].append({'event': 'failure_on', 'time': stamp(), 'elapsed_s': round(time.monotonic() - begin, 3)})
        print('  Failure ON (20 seconds)', flush=True)
        time.sleep(20)
        failure(mode, False)
        injected = False
        meta['events'].append({'event': 'failure_off', 'time': stamp(), 'elapsed_s': round(time.monotonic() - begin, 3)})
        print('  Failure OFF; waiting for traffic completion...', flush=True)
        # Wall-clock cap, even if Docker exec or iperf stalls.
        limit = 70 if proto == 'icmp' else 100
        remaining = max(2, limit - (time.monotonic() - begin))
        try:
            rc = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            # A stalled traditional TCP flow is an experimental outcome, not a runner crash.
            meta['traffic_timed_out'] = True
            meta['note'] = f'Traffic did not exit within {limit}s; classified as incomplete session'
            name = 'ping' if proto == 'icmp' else 'iperf3'
            run(['docker', 'exec', 'seamlessnet-client', 'pkill', '-INT', '-x', name], timeout=12, check=False)
            try:
                rc = proc.wait(timeout=7)
            except subprocess.TimeoutExpired:
                run(['docker', 'exec', 'seamlessnet-client', 'pkill', '-KILL', '-x', name], timeout=12, check=False)
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                rc = 124
            print(f'  INCOMPLETE: traffic exceeded {limit}s; saved as session failure', flush=True)
        finally:
            out.close()
        meta['traffic_exit_code'] = rc
        if rc != 0 and 'note' not in meta:
            meta['note'] = 'Nonzero traffic exit; retain as observed result, inspect traffic.txt'
        meta['completed_normally'] = (rc == 0)
        outage_events = {e['event']: e['elapsed_s'] for e in meta['events'] if 'elapsed_s' in e}
        actual_outage = outage_events.get('failure_off', 0) - outage_events.get('failure_on', 0)
        meta['actual_outage_seconds'] = round(actual_outage, 3)
        meta['valid'] = (rc == 0 and 18 <= actual_outage <= 25)
        if not meta['valid']:
            meta['note'] = 'Incomplete traffic or invalid outage timing; do not include in final metrics'
        if rc != 0:
            print('  WARNING: incomplete traffic; metadata marked invalid', flush=True)
        print(f'  Trial recorded; exit code {rc}; completed normally: {rc == 0}', flush=True)
    except Exception as exc:
        meta['error'] = str(exc)
        print(f'  ERROR: {exc}', file=sys.stderr, flush=True)
        raise
    finally:
        if proc is not None and proc.poll() is None:
            # Stop the in-container workload before detaching the Docker CLI.
            name = 'ping' if proto == 'icmp' else 'iperf3'
            try:
                run(['docker', 'exec', 'seamlessnet-client', 'pkill', '-INT', '-x', name], timeout=12, check=False)
            except Exception:
                pass
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if proc is not None:
            try:
                out.close()
            except Exception:
                pass
        if injected:
            try:
                failure(mode, False)
            except Exception as exc:
                meta['cleanup_error'] = str(exc)
        if mode == 'quic':
            try:
                dc('logs', '--since', start_log, 'client', 'server', output=folder / 'quic-events.txt')
            except Exception as exc:
                meta['logs_error'] = str(exc)
        meta['finished_at'] = stamp()
        (folder / 'metadata.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--protocol', choices=['all', 'icmp', 'tcp', 'udp'], default='all')
    parser.add_argument('--mode', choices=['all', 'direct', 'quic'], default='all')
    parser.add_argument('--resume', type=pathlib.Path, help='Existing comparison results directory; skip valid completed trials')
    args = parser.parse_args()
    root = args.resume if args.resume else pathlib.Path('results') / ('comparison-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S'))
    if args.resume and not root.is_dir():
        parser.error(f'Resume directory does not exist: {root}')
    root.mkdir(parents=True, exist_ok=True)
    print('Results:', root, flush=True)
    print('Checking Docker Engine...', flush=True)
    run(['docker', 'info', '--format', '{{.ServerVersion}}'], timeout=90)
    run(['docker', 'inspect', '-f', '{{.Name}} {{.State.Status}}', 'seamlessnet-client', 'seamlessnet-server', 'seamlessnet-web'], timeout=60, output=root / 'container-status.txt')
    # Compose configuration is optional diagnostic data; avoid blocking a benchmark on it.
    try:
        if not args.resume:
            dc('config', timeout=90, output=root / 'compose-config.yaml')
    except Exception as exc:
        (root / 'compose-config-error.txt').write_text(str(exc), encoding='utf-8')
    protocols = ['icmp', 'tcp', 'udp'] if args.protocol == 'all' else [args.protocol]
    modes = ['direct', 'quic'] if args.mode == 'all' else [args.mode]
    try:
        for proto in protocols:
            for mode in modes:
                for n in range(1, args.runs + 1):
                    metadata = root / f'{mode}-{proto}' / f'run-{n:02d}' / 'metadata.json'
                    if metadata.exists():
                        try:
                            previous = json.loads(metadata.read_text(encoding='utf-8'))
                            if previous.get('valid') is True and previous.get('completed_normally') is True and (metadata.parent / 'traffic.txt').exists():
                                print(f'SKIP completed: {mode} {proto} run {n}', flush=True)
                                continue
                            # Older versions recorded valid=True and exit_code=0, without completed_normally.
                            if previous.get('valid') is True and previous.get('traffic_exit_code') == 0 and not previous.get('error') and (metadata.parent / 'traffic.txt').exists():
                                print(f'SKIP completed (older metadata): {mode} {proto} run {n}', flush=True)
                                continue
                        except (ValueError, OSError):
                            pass
                        backup = metadata.with_name('metadata.previous.json')
                        backup.write_bytes(metadata.read_bytes())
                    trial(root, mode, proto, n)
                    time.sleep(2)
    except Exception:
        print('ABORTED. Partial results saved to', root, file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            clear_direct()
            clear_quic()
            if state('client') == 'running':
                set_mode('quic')
        except Exception as exc:
            print('Cleanup warning:', exc, file=sys.stderr)
    print('COMPLETE:', root, flush=True)


if __name__ == '__main__':
    main()
