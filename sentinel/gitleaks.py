"""Optional stdin adapter. Never persist or display scanner-generated snippets."""
import json
import os
import shutil
import subprocess
import tempfile
import uuid


class Gitleaks:
    def __init__(self):
        self.binary = shutil.which('gitleaks')
        if not self.binary:
            raise RuntimeError('Gitleaks missing')
        result = subprocess.run([self.binary,'version'],capture_output=True,timeout=5,check=True)
        version = result.stdout.decode().strip()
        if not version.startswith('8.'):
            raise RuntimeError('Adapter requires Gitleaks 8.x')
        self.version = 'gitleaks-' + version

    def scan(self, text, path):
        # Isolated cwd avoids untrusted project configuration or ignore files.
        with tempfile.TemporaryDirectory(prefix='sentinel-') as cwd:
            env = {k:v for k,v in os.environ.items() if not k.startswith('GITLEAKS')}
            result = subprocess.run([self.binary,'stdin','--redact=100','--report-format=json',
                '--report-path=-','--no-banner','--log-level=error'],input=text.encode(),
                capture_output=True,timeout=10,cwd=cwd,env=env)
        if result.returncode not in (0,1) or len(result.stdout)>8*1024*1024:
            raise RuntimeError('Scanner failure')
        data = json.loads(result.stdout or b'[]')
        if not isinstance(data,list):
            raise RuntimeError('Invalid scanner report')
        findings=[]
        for item in data[:1000]:
            # Discard rule descriptions, matches, secrets, and all free text.
            line = item.get('StartLine',0)
            findings.append(dict(id=str(uuid.uuid4()),rule='gitleaks-candidate',severity='Medium',
                confidence='candidate',path=path,line=line if type(line) is int else 0,
                evidence='[REDACTED]', validity='not_checked',exposure='local_only',billing='unknown',
                remediation='Review locally and rotate at the issuer if genuine.'))
        return findings
