## MicroPKI
A minimal representation of PKI (Public Key Infrastructure) utility based on Python, that creates self-signed Root CA and generates certificate.

## Dependencies
- **Python**>=3.9
- **cryptography**>=41.0.0
- **pytest**>=7.0.0

## Installation
```bash
git clone {repository_url}
cd MicroPKI
python -m venv .venv
source .venv/bin/activate  #Linux/MacOS
pip install -r requirements.txt
```
## How to start
**Initiaalize Root CA**
```bash
echo "my-cool-passphrase" > phrase.pass
python -m micropki.cli init-ca \
--subject "/CN=Test CA,O=Test Organisation,C=RU" \
--key-type ecc \  #or RSA
--out-dir ./pki_data \
--passphrase-file phrase.pass \
--validity-days 1875  #3650 days max
```
