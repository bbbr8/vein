"""Regression gates for the local-only public source profile."""
import ast
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
DENIED={'http.server','wsgiref','flask','fastapi','uvicorn','socket','requests','httpx','urllib.request'}

def files():
    for path in ROOT.rglob('*'):
        if path.is_file() and not any(p in {'.git','__pycache__','.venv','outputs','state'} for p in path.relative_to(ROOT).parts):
            yield path

class PublicDistribution(unittest.TestCase):
    def test_no_network_server_or_client_imports(self):
        for path in files():
            if path.suffix!='.py':continue
            for node in ast.walk(ast.parse(path.read_text(),filename=str(path))):
                names=[a.name for a in node.names] if isinstance(node,ast.Import) else [node.module or ''] if isinstance(node,ast.ImportFrom) else []
                for name in names:
                    self.assertFalse(any(name==bad or name.startswith(bad+'.') for bad in DENIED),(path.relative_to(ROOT),name))
                if isinstance(node,ast.ImportFrom) and node.module=='urllib':
                    self.assertNotIn('request',[a.name for a in node.names])

    def test_no_credentials_or_personal_machine_paths(self):
        personal=re.compile('/'+'Users'+'/(?!example(?:[^A-Za-z0-9_]|$)|user(?:[^A-Za-z0-9_]|$))[A-Za-z0-9_. -]+',re.I)
        credentials=re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk-(?:proj-)?[A-Za-z0-9_-]{40,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
        for path in files():
            text=path.read_bytes().decode('utf-8',errors='ignore')
            self.assertIsNone(personal.search(text.replace(chr(92),'/')),path.relative_to(ROOT))
            self.assertIsNone(credentials.search(text),path.relative_to(ROOT))

    def test_no_hosting_configuration_or_http_entrypoint(self):
        for name in ['server.py','render.yaml','compose.yaml','Dockerfile','.env','credentials.json','secrets.json']:
            self.assertFalse((ROOT/name).exists(),name)
        self.assertTrue((ROOT/'PUBLIC_DISTRIBUTION.md').is_file())

    def test_policy_documents_local_stdio(self):
        policy=(ROOT/'PUBLIC_DISTRIBUTION.md').read_text()
        self.assertIn('standard input and',policy)
        self.assertIn('do not open a network port',policy)

if __name__=='__main__':unittest.main()
