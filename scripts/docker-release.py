#!/usr/bin/env python3
"""Container release provenance and static ELF policy. Never executes target ELF."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

POLICY = 'ubuntu24.04-x86-64-v1-musl-separate-2'
FLAGS = '-march=x86-64 -mtune=generic'

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run(*args):
    return subprocess.check_output(args, text=True, env={**os.environ, 'LC_ALL': 'C'})

def safe_path(root, relative, kind):
    # Narrow namespaces prevent forced builds from deleting native/other outputs.
    prefix = 'build/docker/' if kind == 'build' else 'install/'
    if not re.fullmatch(r'[A-Za-z0-9_./-]+', relative) or not relative.startswith(prefix):
        raise ValueError(f'{kind} path must be a relative child of {prefix}')
    if any(p in ('', '.', '..') for p in relative.split('/')):
        raise ValueError('unsafe path component')
    base = Path(root).resolve()
    path = base / relative
    for parent in [path, *path.parents]:
        if parent == base:
            break
        if parent.is_symlink():
            raise ValueError('symlink in output path')
    if base not in path.resolve().parents or path.resolve() == base / prefix.rstrip('/'):
        raise ValueError('output path is not a strict namespace child')
    return str(path)

def elf(binary, platform):
    header = run('readelf', '-hW', str(binary))
    if 'ELF64' not in header or 'Advanced Micro Devices X86-64' not in header:
        raise ValueError('release must be ELF64 x86-64')
    program = run('readelf', '-lW', str(binary))
    dynamic = run('readelf', '-dW', str(binary))
    versions = run('readelf', '--version-info', str(binary))
    notes = run('readelf', '-nW', str(binary))
    if re.search(r'x86-64-v[234]|ISA needed:.*(?:AVX|SSE4)', notes, re.I):
        raise ValueError('ELF declares a CPU requirement above x86-64 baseline')
    if re.search(r'\((?:RPATH|RUNPATH)\)', dynamic):
        raise ValueError('release must not carry RPATH/RUNPATH')
    needed = re.findall(r'\(NEEDED\).*\[([^]]+)\]', dynamic)
    if platform == 'ubuntu':
        if '/lib64/ld-linux-x86-64.so.2' not in program or 'musl' in program:
            raise ValueError('expected glibc interpreter')
        allowed = {'libc.so.6', 'libm.so.6', 'libpthread.so.0', 'libdl.so.2', 'librt.so.1',
                   'ld-linux-x86-64.so.2', 'libstdc++.so.6', 'libgcc_s.so.1', 'libssl.so.3', 'libcrypto.so.3'}
        ceilings = {'GLIBC': (2, 39), 'GLIBCXX': (3, 4, 30), 'CXXABI': (1, 3, 13), 'OPENSSL': (3, 0, 0)}
        if 'GLIBC_PRIVATE' in versions or re.search(r'GLIBC_(?:ABI_|[A-Za-z])', versions):
            raise ValueError('unsupported glibc ABI namespace')
        for namespace, ceiling in ceilings.items():
            for value in re.findall(r'\b' + namespace + r'_([0-9]+(?:\.[0-9]+)+)', versions):
                if tuple(map(int, value.split('.'))) > ceiling:
                    raise ValueError(f'{namespace}_{value} exceeds Ubuntu 24.04 policy')
    else:
        if '/lib/ld-musl-x86_64.so.1' not in program or re.search(r'\bGLIBC_', versions):
            raise ValueError('expected musl ELF without glibc versions')
        allowed = {'libc.musl-x86_64.so.1', 'libstdc++.so.6', 'libgcc_s.so.1', 'libssl.so.3', 'libcrypto.so.3'}
    if not needed or set(needed) - allowed:
        raise ValueError(f'unsupported runtime libraries: {needed}')
    return {'policy': POLICY, 'platform': platform, 'needed': sorted(needed), 'cpu_baseline': 'x86-64',
            'cpu_check': 'explicit compiler flags plus ELF GNU property; not an instruction-set proof'}

def commands(path):
    import shlex
    entries = json.loads(Path(path).read_text())
    if not entries:
        raise ValueError('missing compiler command evidence')
    for entry in entries:
        args = entry.get('arguments') or shlex.split(entry['command'])
        if '-march=x86-64' not in args or '-mtune=generic' not in args:
            raise ValueError('compiler command lacks explicit CPU baseline')
        for arg in args:
            baseline_options = {'-march=x86-64', '-mtune=generic', '-m64', '-msse', '-msse2', '-mmmx', '-mstackrealign'}
            if ((arg.startswith('-m') and arg not in baseline_options and not arg.startswith('-mno-')) or
                arg.startswith(('@', '-Xclang', '-Xassembler', '-Wa,'))):
                raise ValueError('compiler command raises or obscures CPU baseline: ' + arg)


def inputs(args):
    root = Path(args.root)
    image = args.image
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('immutable Docker image ID required')
    head = run('git', '-C', str(root), 'rev-parse', 'HEAD').strip()
    status = run('git', '-C', str(root), 'status', '--porcelain', '--untracked-files=normal').strip()
    submodules = run('git', '-C', str(root), 'submodule', 'status', '--recursive').strip()
    dirty_submodules = run('git', '-C', str(root), 'submodule', 'foreach', '--quiet', '--recursive',
                           'git status --porcelain --untracked-files=normal').strip()
    tracked_diff = run('git', '-C', str(root), 'diff', 'HEAD', '--binary')
    # Hash tracked edits and only these known untracked implementation files.
    # Unknown untracked files (which might contain secrets) are never opened.
    known_untracked = {'scripts/docker-release.py', 'scripts/docker-release-common.sh',
                       'install-service-selfhost/scripts/test_docker_release.py'}
    untracked = set(filter(None, run('git', '-C', str(root), 'ls-files', '--others',
                                    '--exclude-standard', '-z').split('\0')))
    complete = (not (untracked - known_untracked) and not dirty_submodules
                and not (root / 'CMakeUserPresets.json').exists()
                and not any(line.startswith(('-', '+', 'U')) for line in submodules.splitlines()))
    data = {'policy': POLICY, 'platform': args.platform, 'image_id': image, 'preset': args.preset,
            'git_describe': args.describe, 'target': args.target, 'build_dir': args.build_dir, 'install_prefix': args.install_prefix,
            'git_head': head, 'submodules': submodules, 'compiler_flags': FLAGS,
            'git_dirty': bool(status), 'source_snapshot_complete': complete,
            'untracked_paths_sha256': hashlib.sha256('\0'.join(sorted(untracked)).encode()).hexdigest(),
            'tracked_diff_sha256': hashlib.sha256(tracked_diff.encode()).hexdigest(),
            'vcpkg_commit': args.vcpkg_commit, 'vcpkg_tool_sha256': args.tool_sha,
            'vcpkg_tool_url': args.tool_url,
            'files': {p: sha(root / p) for p in ['scripts/docker-release.py', 'scripts/docker-release-common.sh',
                     'scripts/build-ubuntu-docker.sh', 'scripts/build-alpine-docker.sh',
                     'docker/ubuntu-builder.Dockerfile', 'docker/alpine-builder.Dockerfile',
                     'CMakePresets.json', 'vcpkg.json', 'vcpkg-configuration.json',
                     'my-triplets/x64-linux-cpp20.cmake', 'my-triplets/x64-linux-musl.cmake']}}
    for relative in sorted(known_untracked):
        if (root / relative).is_file():
            data['files'][relative] = sha(root / relative)
    fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    return {'fingerprint': fingerprint, 'inputs': data, 'reusable': complete}

def verify(args):
    manifest = json.loads(Path(args.manifest).read_text())
    if manifest.get('schema') != 2 or manifest.get('platform') != 'linux-' + args.platform + '-docker':
        raise ValueError('missing or incompatible container provenance; rebuild required')
    evidence = manifest['environment']
    if evidence.get('platform') != args.platform:
        raise ValueError('libc family does not match provenance')
    if evidence.get('policy') != POLICY or evidence.get('compiler_flags') != FLAGS:
        raise ValueError('obsolete compiler/policy evidence; rebuild required')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', evidence.get('image_id', '')):
        raise ValueError('missing immutable image provenance')
    if manifest.get('git_describe') != evidence.get('git_describe'):
        raise ValueError('release version not bound to environment')
    if (not manifest.get('toolchain', {}).get('packages') or
        not manifest['toolchain'].get('compile_commands_sha256') or manifest['toolchain'].get('compiler_flags') != FLAGS):
        raise ValueError('missing toolchain evidence')
    if manifest.get('fingerprint') != hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest():
        raise ValueError('invalid environment fingerprint')
    if args.expected and manifest['fingerprint'] != json.loads(Path(args.expected).read_text())['fingerprint']:
        raise ValueError('build environment changed; rebuild required')
    if args.expected and (not manifest.get('reusable') or not json.loads(Path(args.expected).read_text())['reusable']):
        raise ValueError('incomplete source snapshot cannot be reused')
    if manifest['binary_sha256'] != sha(args.binary):
        raise ValueError('binary hash mismatch; rebuild required')
    current = elf(args.binary, args.platform)
    if current != manifest['validation']:
        raise ValueError('ELF validation evidence mismatch')
    return manifest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    path = sub.add_parser('path')
    path.add_argument('root'); path.add_argument('relative'); path.add_argument('kind', choices=['build', 'install'])
    cmds = sub.add_parser('commands')
    cmds.add_argument('--path', required=True)
    inp = sub.add_parser('inputs')
    for name in ['root', 'platform', 'image', 'preset', 'target', 'build-dir', 'install-prefix', 'vcpkg-commit', 'tool-sha', 'tool-url', 'describe']:
        inp.add_argument('--' + name, required=True)
    for action in ['verify', 'record', 'elf']:
        p = sub.add_parser(action)
        p.add_argument('--binary', required=True); p.add_argument('--platform', choices=['ubuntu', 'alpine'], required=True)
        if action != 'elf':
            p.add_argument('--manifest', required=True); p.add_argument('--expected')
        if action == 'record':
            p.add_argument('--describe', required=True); p.add_argument('--toolchain', required=True)
    args = parser.parse_args()
    if args.action == 'path':
        print(safe_path(args.root, args.relative, args.kind))
    elif args.action == 'commands':
        commands(args.path)
    elif args.action == 'inputs':
        print(json.dumps(inputs(args), sort_keys=True))
    elif args.action == 'elf':
        print(json.dumps(elf(args.binary, args.platform), sort_keys=True))
    elif args.action == 'verify':
        verify(args)
    else:
        expected = json.loads(Path(args.expected).read_text())
        toolchain = json.loads(Path(args.toolchain).read_text())
        if toolchain.get('compiler_flags') != FLAGS or not toolchain.get('cxx_version') or not toolchain.get('packages') or not toolchain.get('compile_commands_sha256'):
            raise ValueError('missing in-container toolchain evidence')
        manifest = {'schema': 2, 'platform': 'linux-' + args.platform + '-docker',
                    'git_head': expected['inputs']['git_head'], 'git_describe': args.describe,
                    'git_dirty': expected['inputs']['git_dirty'],
                    'build_target': expected['inputs']['target'], 'fingerprint': expected['fingerprint'],
                    'environment': expected['inputs'], 'toolchain': toolchain, 'reusable': expected['reusable'],
                    'binary_sha256': sha(args.binary), 'validation': elf(args.binary, args.platform),
                    'timestamp_utc': datetime.now(timezone.utc).isoformat()}
        dest = Path(args.manifest)
        temp = dest.with_suffix('.json.tmp')
        temp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        temp.replace(dest)

if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f'docker-release: {error}', file=sys.stderr)
        sys.exit(1)
