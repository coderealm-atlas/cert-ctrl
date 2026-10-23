#!/usr/bin/env python3
"""Local-only tests: mock Docker/remote actions; compile a tiny CMake fixture, never run ELF."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release', ROOT / 'scripts/docker-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

class PolicyTest(unittest.TestCase):
    def test_paths_reject_escape_native_parent_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'install').mkdir()
            (root / 'install/link').symlink_to('/tmp')
            for value, kind in [('build/release','build'),('build/docker','build'),
                                ('build/docker/../native','build'),('/tmp/output','build'),
                                ('install','install'),('install/link/bin','install'),
                                ('install/a;touch','install'),('build/docker//x','build')]:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    release.safe_path(root,value,kind)
            self.assertEqual(release.safe_path(root,'build/docker/ubuntu/release','build'),
                             str(root/'build/docker/ubuntu/release'))

    def inspect(self, platform='ubuntu', versions='GLIBC_2.39', needed='libc.so.6', notes='', dynamic=''):
        program = '/lib64/ld-linux-x86-64.so.2' if platform=='ubuntu' else '/lib/ld-musl-x86_64.so.1'
        with patch.object(release,'run',side_effect=['ELF64 Advanced Micro Devices X86-64',program,
                         f'(NEEDED) Shared library: [{needed}]\n'+dynamic,versions,notes]):
            return release.elf('/never/executed',platform)

    def test_ubuntu_24_ceiling_and_unknown_dependencies_fail_closed(self):
        self.inspect()
        for changes in [{'versions':'GLIBC_2.40'}, {'versions':'GLIBC_PRIVATE'},
                        {'versions':'GLIBC_ABI_DT_RELR'}, {'versions':'GLIBCXX_3.4.34'},
                        {'versions':'OPENSSL_3.5.0'}, {'needed':'libunavailable.so'}, {'notes':'x86 ISA needed: x86-64-v3'},
                        {'dynamic':'(RUNPATH) [/home/builder]'}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.inspect(**changes)

    def test_cpu_flags_reject_native_extensions_and_response_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'commands.json'
            baseline=['cc','-march=x86-64','-mtune=generic','-c','main.c']
            path.write_text(json.dumps([{'arguments':baseline}]))
            release.commands(path)
            for extra in ['-march=native','-mavx2','-mcpu=haswell','-mpopcnt','-msha','-Xclang','@hidden.rsp']:
                path.write_text(json.dumps([{'arguments':baseline+[extra]}]))
                with self.subTest(extra=extra),self.assertRaises(ValueError):
                    release.commands(path)

    def test_bad_vcpkg_checksum_is_rejected_before_execution(self):
        text=(ROOT/'scripts/build-ubuntu-docker.sh').read_text()
        function=text[text.index('validate_vcpkg_tool() {'):text.index('\nif validate_vcpkg_tool')]
        function=function.replace('\\$','$')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);tool=root/'tool';marker=root/'executed'
            tool.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\n')
            tool.chmod(0o755)
            result=subprocess.run(['bash','-c',function+'\nvalidate_vcpkg_tool "$1"','test',str(tool)],
                                  env={**os.environ,'VCPKG_TOOL_SHA512':'0'*128},capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(marker.exists())

    def test_musl_policy_is_separate(self):
        self.inspect('alpine',versions='',needed='libc.musl-x86_64.so.1')
        with self.assertRaises(ValueError):
            self.inspect('alpine',versions='GLIBC_2.34',needed='libc.musl-x86_64.so.1')
        with self.assertRaises(ValueError):
            self.inspect('ubuntu',needed='libc.musl-x86_64.so.1')

class WiringTest(unittest.TestCase):
    def test_packaging_validates_source_and_staged_binary_before_tar(self):
        import yaml
        tasks = yaml.safe_load((ROOT/'install-service-selfhost/ansible/roles/install_service_package_posix/tasks/main.yml').read_text())
        gates = [t for t in tasks if 'Validate Linux Docker provenance' in t['name']]
        self.assertEqual(len(gates),2)
        for gate in gates:
            argv = gate['command']['argv']
            self.assertIn('verify',argv)
            self.assertIn('--platform',argv)
            self.assertIn('install_service_docker_platform',gate['when'])
            self.assertNotIn('ignore_errors',gate)
        self.assertLess(tasks.index(gates[0]),next(i for i,t in enumerate(tasks) if t['name']=='Stage binary for packaging'))
        self.assertLess(tasks.index(gates[1]),next(i for i,t in enumerate(tasks) if t['name']=='Create archive'))
        self.assertIn('install_service_package_tmp',gates[1]['command']['argv'][-1])
        jobs=yaml.safe_load((ROOT/'install-service-selfhost/ansible/group_vars/build_linux_docker.yml').read_text())['install_service_linux_docker_jobs']
        self.assertEqual([j['platform'] for j in jobs],['ubuntu','alpine'])
        play=(ROOT/'install-service-selfhost/ansible/playbooks/build_release.yml').read_text()
        self.assertIn("install_service_docker_platform: \"{{ docker_job.platform | default(",play)

    def test_no_broad_delete_or_build_preset_and_checksums_precede_execution(self):
        for platform in ['ubuntu','alpine']:
            text=(ROOT/f'scripts/build-{platform}-docker.sh').read_text()
            self.assertNotIn('rm -rf /work/build',text)
            self.assertNotIn('cmake --build --preset',text)
            self.assertIn('cmake --preset "${PRESET}" -B "${BUILD_DIR}" --fresh',text)
            self.assertLess(text.index('sha512sum -c'),text.index('timeout 10s'))
            self.assertIn('CERTCTRL_CPU_BASELINE=x86-64',text)
            self.assertIn('"${RELEASE_IMAGE_ID}" bash',text)

class IntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo=Path(self.temp.name)/'repo';self.repo.mkdir()
        for name in ['scripts','docker','my-triplets']:
            (self.repo/name).mkdir()
        for name in ['docker-release.py','docker-release-common.sh','build-ubuntu-docker.sh','build-alpine-docker.sh']:
            shutil.copyfile(ROOT/'scripts'/name,self.repo/'scripts'/name)
        for name in ['ubuntu','alpine']:
            shutil.copyfile(ROOT/f'docker/{name}-builder.Dockerfile',self.repo/f'docker/{name}-builder.Dockerfile')
        for name in ['x64-linux-cpp20','x64-linux-musl']:
            shutil.copyfile(ROOT/f'my-triplets/{name}.cmake',self.repo/f'my-triplets/{name}.cmake')
        for name in ['vcpkg.json','vcpkg-configuration.json']:
            (self.repo/name).write_text('{}')
        (self.repo/'CMakePresets.json').write_text(json.dumps({'version':4,'configurePresets':[
            {'name':'release','generator':'Ninja','binaryDir':'${sourceDir}/build/release',
             'cacheVariables':{'CMAKE_BUILD_TYPE':'Release','CMAKE_EXPORT_COMPILE_COMMANDS':'ON'}},
            {'name':'release-other','inherits':'release'}]}))
        (self.repo/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.24)\nproject(Fixture C)\nadd_executable(cert_ctrl main.c)\nadd_executable(other main.c)\ninstall(TARGETS cert_ctrl other RUNTIME DESTINATION bin OPTIONAL)\n')
        (self.repo/'main.c').write_text('int main(void){return 0;}\n')
        (self.repo/'toolchain.cmake').write_text('')
        metadata=self.repo/'external/vcpkg/scripts';metadata.mkdir(parents=True)
        (metadata/'vcpkg-tool-metadata.txt').write_text('VCPKG_TOOL_RELEASE_TAG=test\nVCPKG_GLIBC_SHA='+'a'*128+'\n')
        (self.repo/'.gitignore').write_text('build/\ninstall/\n.cache/\n')
        self.git('init','-q');self.git('add','.');self.commit()
        self.bin=Path(self.temp.name)/'bin';self.bin.mkdir()
        docker=self.bin/'docker'
        docker.write_text('''#!/usr/bin/env python3
import json,os,pathlib,subprocess,sys
args=sys.argv[1:]
with open(os.environ['DOCKER_TEST_LOG'],'a') as f: f.write(json.dumps(args)+'\\n')
if args[0]=='image': print('sha256:'+os.environ.get('TEST_IMAGE_BYTE','a')*64)
elif args[0]=='run':
    command=args[-1]
    # Run only the configure/build/install block using real CMake, no networking/vcpkg/application.
    command=command[command.index('cmake --preset'):]
    command=command.replace('${TMP_VCPKG}', '/tmp/vcpkg-gnu')
    command=command.replace('/work',os.environ['TEST_REPO']).replace('/tmp/vcpkg-gnu/scripts/buildsystems/vcpkg.cmake',os.environ['TEST_REPO']+'/toolchain.cmake')
    env={**os.environ,'CC':'cc','CXX':'c++'}
    sys.exit(subprocess.call(['bash','-euc',command],cwd=os.environ['TEST_REPO'],env=env))
elif args[0]!='build': sys.exit(3)
''')
        docker.chmod(0o755)
        self.log=Path(self.temp.name)/'docker.log'
        self.env={**os.environ,'PATH':str(self.bin)+':'+os.environ['PATH'],'TEST_REPO':str(self.repo),
                  'DOCKER_TEST_LOG':str(self.log),'VCPKG_COMMIT':'fixture',
                  'VCPKG_CACHE_ROOT':str(Path(self.temp.name)/'cache'),
                  'BUILD_DIR_REL':'build/docker/ubuntu/custom','INSTALL_PREFIX_REL':'install/selfhost-release'}
        for key in ['INSTALL_SERVICE_FORCE_BUILD','INSTALL_SERVICE_RECONFIG_CMAKE','BUILD_TARGET','IMAGE_NAME']:
            self.env.pop(key,None)

    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.repo),*args],text=True,stderr=subprocess.DEVNULL)
    def commit(self):
        self.git('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','fixture')
    def build(self,preset="release",**env):
        p=subprocess.run(['bash',str(self.repo/'scripts/build-ubuntu-docker.sh'),preset],env={**self.env,**env},capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        return p
    def runs(self):
        return len([a for a in map(json.loads,self.log.read_text().splitlines()) if a[0]=='run'])
    def test_actual_output_reuse_environment_hash_and_force_safety(self):
        native=self.repo/'build/release';native.mkdir(parents=True)
        sentinel=native/'keep';sentinel.write_text('native cache')
        self.build()
        selected=self.repo/'build/docker/ubuntu/custom'
        self.assertTrue((selected/'cert_ctrl').is_file())
        self.assertFalse((native/'cert_ctrl').exists())
        manifest=self.repo/'install/selfhost-release/build-info.json'
        original=manifest.read_bytes()
        self.assertEqual(self.runs(),1)
        self.build();self.assertEqual(self.runs(),1)
        self.assertEqual(original,manifest.read_bytes(),'reuse must not rewrite provenance')
        binary=self.repo/'install/selfhost-release/bin/cert_ctrl'
        with binary.open('ab') as f:f.write(b'tampered')
        self.build();self.assertEqual(self.runs(),2)
        stale=selected/'stale-object.o';stale.write_text('previous toolchain')
        self.build(TEST_IMAGE_BYTE='b');self.assertEqual(self.runs(),3)
        self.assertFalse(stale.exists(),'environment mismatch must discard old objects')
        manifest.write_text('{"git_describe":"old"}')
        self.build(TEST_IMAGE_BYTE='b');self.assertEqual(self.runs(),4)
        self.build(TEST_IMAGE_BYTE='b',INSTALL_SERVICE_FORCE_BUILD='1');self.assertEqual(self.runs(),5)
        self.assertEqual(sentinel.read_text(),'native cache')
        self.assertTrue((selected/'.release.lock').exists())
        metadata=json.loads(manifest.read_text())
        self.assertEqual(metadata['binary_sha256'],hashlib.sha256(binary.read_bytes()).hexdigest())
        self.assertEqual(metadata['environment']['image_id'],'sha256:'+'b'*64)
        self.assertEqual(metadata['validation']['platform'],'ubuntu')
        all_calls=list(map(json.loads,self.log.read_text().splitlines()))
        self.assertTrue(all(args[-1]==str(self.repo/'docker') for args in all_calls if args[0]=='build'))
        run=next(a for a in all_calls if a[0]=='run')
        self.assertTrue(any('/ubuntu/'+'a'*64 in a for a in run),'cache must be image/libc isolated')

    def test_invalid_override_rejected_before_docker(self):
        for path in ['build/release','build/docker/../native','/tmp/other']:
            p=subprocess.run(['bash',str(self.repo/'scripts/build-ubuntu-docker.sh')],
                             env={**self.env,'BUILD_DIR_REL':path},capture_output=True,text=True)
            self.assertNotEqual(p.returncode,0)
        self.assertFalse(self.log.exists())

    def test_preset_target_and_directory_changes_reject_reuse(self):
        self.build()
        self.build(preset='release-other')
        self.assertEqual(self.runs(),2)
        self.build(preset='release-other',BUILD_TARGET='other')
        self.assertEqual(self.runs(),3)
        self.build(preset='release-other',BUILD_TARGET='other',BUILD_DIR_REL='build/docker/ubuntu/second')
        self.assertEqual(self.runs(),4)
        self.assertTrue((self.repo/'build/docker/ubuntu/second/other').is_file())

    def test_unknown_untracked_source_disables_reuse_without_reading_it(self):
        self.build()
        # An unknown input is not trusted to be part of the hashed source snapshot.
        (self.repo/'unknown.cpp').write_text('untracked input')
        self.build();self.build()
        self.assertEqual(self.runs(),3)

    def test_changed_source_rebuilds_then_identical_dirty_snapshot_reuses(self):
        self.build()
        (self.repo/'main.c').write_text('int main(void){return 1;}\n')
        self.build();self.build()
        self.assertEqual(self.runs(),2,'identical fully hashed tracked edits may reuse')

if __name__=='__main__':
    unittest.main()
