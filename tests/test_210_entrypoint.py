"""Regression: installed CLI must find autoban.py from an unrelated working dir.

The old 2.0.9 installer copied fw_sentinel.py to /usr/local/sbin where Python
could not find autoban.py from /usr/local/lib/fw-sentinel.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class InstalledEntrypointTests(unittest.TestCase):
    def test_installer_installs_wrapper_and_smoke_checks_real_binary(self):
        installer=(ROOT/'install.sh').read_text(encoding='utf-8')
        self.assertIn('install -m 0755 bin/fw-sentinel /usr/local/sbin/fw-sentinel',installer)
        self.assertIn('/usr/local/sbin/fw-sentinel --version',installer)
        self.assertIn('import fw_sentinel, autoban, webui, ipmeta',installer)
        self.assertLess(installer.index('/usr/local/sbin/fw-sentinel --version'),installer.index('systemctl daemon-reload'))

    def test_bin_launcher_resolves_autoban_from_installed_lib_not_sbin(self):
        source=(ROOT/'bin/fw-sentinel').read_text(encoding='utf-8')
        self.assertIn('exec /usr/bin/python3 -u /usr/local/lib/fw-sentinel/fw_sentinel.py "$@"',source)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            lib=root/'lib'
            bin_dir=root/'sbin'
            lib.mkdir();bin_dir.mkdir()
            shutil.copy2(ROOT/'fw_sentinel.py',lib/'fw_sentinel.py')
            shutil.copy2(ROOT/'autoban.py',lib/'autoban.py')
            shutil.copy2(ROOT/'i18n.py',lib/'i18n.py')
            shutil.copy2(ROOT/'provider_keys.py',lib/'provider_keys.py')
            wrapper=bin_dir/'fw-sentinel'
            wrapper.write_text(source.replace('/usr/local/lib/fw-sentinel/fw_sentinel.py',str(lib/'fw_sentinel.py')),encoding='utf-8')
            wrapper.chmod(0o755)
            process=subprocess.run([str(wrapper),'--version'],cwd=bin_dir,capture_output=True,text=True,timeout=15)
            self.assertEqual(process.returncode,0,process.stderr)
            self.assertEqual(process.stdout.strip(),'FW Sentinel 2.0.21')
            # No copy of autoban.py beside the command, unlike the stopgap workaround.
            self.assertFalse((bin_dir/'autoban.py').exists())

    def test_version_matches_browser_config_and_installer(self):
        import json
        self.assertEqual(json.loads((ROOT/'config.json').read_text())['version'],'2.0.21')
        self.assertIn('FW SENTINEL <small class="muted">2.0.21',(ROOT/'webui.py').read_text())
        self.assertIn('FW SENTINEL 2.0.21',(ROOT/'install.sh').read_text())

if __name__=='__main__':
    unittest.main()
