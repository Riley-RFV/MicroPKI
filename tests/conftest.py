import pytest
import tempfile
import shutil
from pathlib import Path
import os
import sys
import warnings

warnings.filterwarnings("ignore", category=RuntimeWarning, module="runpy")

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

@pytest.fixture
def temp_dir():
    dirpath = tempfile.mkdtemp()
    yield Path(dirpath)
    shutil.rmtree(dirpath)

@pytest.fixture
def passphrase_file(temp_dir):
    pass_path = temp_dir / "pass.txt"
    pass_path.write_text("TestPassphrase123!")
    return pass_path

@pytest.fixture
def inv_passphrase_file(temp_dir):
    pass_path = temp_dir / "wrong_pass.txt"
    pass_path.write_text("WrongPassword!")
    return pass_path

@pytest.fixture
def non_existent_file(temp_dir):
    return temp_dir / "does_not_exist.txt"

@pytest.fixture
def unwritable_dir():
    if os.name == 'nt':
        pytest.skip("Unix permissions test skipped on Windows")
    
    dirpath = tempfile.mkdtemp()
    os.chmod(dirpath, 0o444)
    yield Path(dirpath)
    os.chmod(dirpath, 0o755)
    shutil.rmtree(dirpath)

@pytest.fixture
def ca_initialized(temp_dir, passphrase_file):
    from micropki.ca import RootCA
    
    ca = RootCA(str(temp_dir))
    ca.initialize(
        subject="CN=Test CA,O=Test Org",
        key_type="rsa",
        key_size=4096,
        passphrase=passphrase_file.read_bytes(),
        validity_days=365
    )
    return {
        'ca': ca,
        'out_dir': temp_dir,
        'cert_path': temp_dir / "certs" / "ca.cert.pem",
        'key_path': temp_dir / "private" / "ca.key.pem",
        'passphrase': passphrase_file.read_bytes()
    }
