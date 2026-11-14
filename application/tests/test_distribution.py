"""Offline installer regressions. Standard library only; no Docker daemon needed."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[2]
FAKE_DOCKER = r'''
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
state=Path(os.environ['TEST_DOCKER_STATE'])
with Path(os.environ['TEST_DOCKER_LOG']).open('a') as f:f.write(json.dumps(args)+'\n')
if args[0]=='info':
 if '--format' in args:print('["name=apparmor"]' if 'SecurityOptions' in args[-1] else 'linux/x86_64')
elif args[0]=='version':print('1.56')
elif args[:2]==['image','inspect']:
 if not state.exists():sys.exit(1)
 print('sha256:'+'1'*64)
elif args[:2]==['image','load']:state.touch()
elif args[0]=='buildx':print('Buildx available for explicit/source builds')
elif args[0]=='compose':
 if 'version' in args:print('Docker Compose version v5')
 elif '--help' in args:print('--wait')
 elif 'config' in args:
  print('\n'.join('odysafe-source-'+name+':1.0.0' for name in ['app','interactive','fixture','gateway','proxy']))
 elif 'port' in args:print('127.0.0.1:8443')
 elif 'build' in args:state.touch()
 elif 'up' in args:pass
 else:sys.exit(92)
else:sys.exit(93)
'''


class OfflineInstaller(unittest.TestCase):
    def setUp(self):
        self.temporary=TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.release=self.root/'release'
        (self.release/'application').mkdir(parents=True)
        for name in ('start.dh','application/common.sh','application/compose.json','application/release-images.env'):
            shutil.copyfile(ROOT/name,self.release/name)
        (self.root/'bin').mkdir()
        docker=self.root/'bin/docker'
        docker.write_text('#!'+sys.executable+'\n'+FAKE_DOCKER)
        docker.chmod(0o755)
        self.env=dict(os.environ,PATH=str(self.root/'bin')+':'+os.environ['PATH'],
                      ODYSAFE_INSTALL_CONFIG=str(self.root/'settings/installation.env'),
                      TEST_DOCKER_STATE=str(self.root/'installed'),TEST_DOCKER_LOG=str(self.root/'docker.log'))

    def run_installer(self,*args):
        return subprocess.run(['sh',str(self.release/'start.dh'),*args],env=self.env,cwd=self.root,
                              text=True,capture_output=True)

    def commands(self):
        return [json.loads(line) for line in (self.root/'docker.log').read_text().splitlines()]

    def bundle(self, valid=True):
        data=b'Fake Docker image archive for installer tests'
        (self.release/'images.tar').write_bytes(data)
        digest=hashlib.sha256(data).hexdigest() if valid else '0'*64
        (self.release/'images.tar.sha256').write_text(digest+'  images.tar\n')
        (self.release/'images.ids').write_text(''.join('sha256:'+'1'*64+'  odysafe-source-'+name+':1.0.0\n' for name in ('app','interactive','fixture','gateway','proxy')))

    def test_fresh_offline_install_imports_verified_bundle_without_build_or_pull(self):
        self.bundle()
        result=self.run_installer()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        calls=self.commands()
        self.assertEqual(sum(call[:2]==['image','load'] for call in calls),1)
        self.assertTrue(any(('up' in call and '--help' not in call) for call in calls))
        self.assertFalse(any('pull' in call or 'build' in call or 'buildx' in call for call in calls))
        self.assertIn('--no-build',next(call for call in calls if ('up' in call and '--help' not in call)))
        self.assertEqual((self.root/'settings/installation.env').stat().st_mode & 0o777,0o600)

    def test_restart_reuses_installed_images_without_reimport(self):
        (self.root/'installed').touch()
        self.bundle()
        result=self.run_installer()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(any(call[:2]==['image','load'] for call in self.commands()))

    def test_checksum_mismatch_never_loads_or_starts(self):
        self.bundle(valid=False)
        result=self.run_installer()
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(call[:2]==['image','load'] or ('up' in call and '--help' not in call) for call in self.commands()))

    def test_missing_bundle_never_downloads_or_builds_in_offline_mode(self):
        result=self.run_installer('--offline')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('complete ODYSAFE offline bundle',result.stderr)
        self.assertFalse(any('pull' in call or 'build' in call or 'buildx' in call for call in self.commands()))

    def test_prepare_only_does_not_start_services(self):
        self.bundle()
        result=self.run_installer('--prepare-only')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(any(('up' in call and '--help' not in call) for call in self.commands()))

    def test_image_id_mismatch_is_rejected(self):
        (self.root/'installed').touch()
        (self.release/'images.ids').write_text('sha256:'+'2'*64+'  odysafe-source-app:1.0.0\n')
        result=self.run_installer()
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(('up' in call and '--help' not in call) for call in self.commands()))

    def test_import_and_build_cannot_be_combined(self):
        result=self.run_installer('--load-images','images.tar','--build')
        self.assertEqual(result.returncode,2)
        self.assertFalse((self.root/'docker.log').exists())

    def test_source_checkout_builds_missing_images_on_first_start(self):
        result=self.run_installer()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertTrue(any('build' in call for call in self.commands()))
        self.assertTrue(any('up' in call and '--help' not in call for call in self.commands()))
        self.assertFalse(any('pull' in call for call in self.commands()))

    def test_offline_bundle_with_missing_archive_does_not_fall_back_to_build(self):
        self.bundle()
        (self.release/'images.tar').unlink()
        result=self.run_installer()
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any('build' in call or 'buildx' in call for call in self.commands()))

    def test_successful_import_can_remove_only_the_extracted_image_archive(self):
        self.bundle()
        result=self.run_installer('--offline','--prepare-only','--remove-image-archive')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.release/'images.tar').exists())
        self.assertFalse((self.release/'images.tar.sha256').exists())
        self.assertTrue((self.release/'images.ids').exists())
        self.assertTrue((self.root/'installed').exists())

    def test_corrupt_image_archive_is_preserved_for_inspection(self):
        self.bundle(valid=False)
        result=self.run_installer('--offline','--remove-image-archive')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue((self.release/'images.tar').exists())

    def test_installed_bundle_can_remove_duplicate_archive_without_reimport(self):
        self.bundle()
        (self.root/'installed').touch()
        result=self.run_installer('--offline','--prepare-only','--remove-image-archive')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.release/'images.tar').exists())
        self.assertFalse(any(call[:2]==['image','load'] for call in self.commands()))


class BundleSourcePolicy(unittest.TestCase):
    def test_bundle_source_inventory_excludes_development_state(self):
        spec=importlib.util.spec_from_file_location('package_offline',ROOT/'tools/package-offline.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        files=module.source_files()
        self.assertTrue(files)
        for path in files:
            relative=path.relative_to(ROOT)
            self.assertFalse(set(relative.parts)&module.BLOCKED)
        self.assertEqual(len(module.image_references()),5)
