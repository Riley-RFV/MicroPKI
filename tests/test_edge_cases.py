import pytest
import subprocess
import sys
from pathlib import Path

def run_cli(args, expect_failure=True):
    cmd = [sys.executable, "-m", "micropki.cli"] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result

def check_error_output(result, expected_text):
    stdout_clean = '\n'.join(
        line for line in result.stdout.split('\n') 
        if 'RuntimeWarning' not in line and 'frozen runpy' not in line
    )
    stderr_clean = '\n'.join(
        line for line in result.stderr.split('\n') 
        if 'RuntimeWarning' not in line and 'frozen runpy' not in line
    )
    
    combined = (stdout_clean + stderr_clean).lower()
    return expected_text.lower() in combined


def test_missing_subj(temp_dir, passphrase_file):
    result = run_cli([
        "init-ca",
        "--out-dir", str(temp_dir),
        "--passphrase-file", str(passphrase_file)
    ])
    
    assert result.returncode != 0, "Should fail without --subject"
    assert check_error_output(result, "required") or check_error_output(result, "error")

def test_ecc_wrong_key_size(temp_dir, passphrase_file):
    """Тест 4: ECC с неподдерживаемым размером ключа (256 бит)"""
    result = run_cli([
        "init-ca",
        "--out-dir", str(temp_dir / "ecc_256"),
        "--subject", "CN=Test",
        "--key-type", "ecc",
        "--key-size", "256",
        "--passphrase-file", str(passphrase_file)
    ])
    
    assert result.returncode != 0, "Should fail with unsupported ECC key size"
    assert check_error_output(result, "invalid") or check_error_output(result, "error")

def test_non_exist_pass(temp_dir):
    """Тест 4: Несуществующий файл с паролем"""
    result = run_cli([
        "init-ca",
        "--out-dir", str(temp_dir / "no_pass"),
        "--subject", "CN=Test",
        "--passphrase-file", str(temp_dir / "does_not_exist.txt")
    ])
    
    assert result.returncode != 0, "Should fail with non-existent passphrase file"
    assert check_error_output(result, "not found"), f"Expected 'not found' in output. Got stdout: {result.stdout}, stderr: {result.stderr}"

def test_unwr_output_dir(unwritable_dir, passphrase_file):
    """Тест 4: Невозможность записи в выходную директорию"""
    result = run_cli([
        "init-ca",
        "--out-dir", str(unwritable_dir / "ca"),
        "--subject", "CN=Test",
        "--passphrase-file", str(passphrase_file)
    ])
    
    assert result.returncode != 0, "Should fail with unwritable directory"
    assert check_error_output(result, "invalid") or check_error_output(result, "error")

def test_rsa_wrong_key_size(temp_dir, passphrase_file):
    """Тест 4: RSA с неподдерживаемым размером (например, 1024)"""
    result = run_cli([
        "init-ca",
        "--out-dir", str(temp_dir / "rsa_1024"),
        "--subject", "CN=Test",
        "--key-type", "rsa",
        "--key-size", "1024",  
        "--passphrase-file", str(passphrase_file)
    ])
    
    assert result.returncode != 0, "Should fail with invalid RSA key size"
    assert check_error_output(result, "invalid") or check_error_output(result, "error")

def test_ca__inited(ca_initialized, passphrase_file):
    temp_dir = ca_initialized['out_dir']
    
    result = run_cli([
        "init-ca",
        "--out-dir", str(temp_dir),
        "--subject", "CN=Another CA",
        "--passphrase-file", str(passphrase_file)
    ])
    
    assert result.returncode != 0, "Should fail when CA already exists"
    assert check_error_output(result, "exists") or check_error_output(result, "already"), \
        f"Expected 'exists' or 'already' in output. Got stdout: {result.stdout}, stderr: {result.stderr}"
