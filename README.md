## MicroPKI
A minimal representation of PKI (Public Key Infrastructure) utility based on Python, that creates self-signed Root CA and generates certificate.

## Dependencies
- **Python**>=3.9
- **cryptography**>=42.0.0
- **pytest**>=7.0.0

## Installation
```bash
git clone {repository_url}
cd MicroPKI
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
## How to start
**1) Initialize Root CA and Database**
```bash
mkdir -p secrets
echo "my-cool-passphrase" > secrets/root.pass

python -m micropki.cli db init --db-path ./pki/micropki.db

python -m micropki.cli ca init \
  --subject "CN=Test Root CA,O=TestOrg,C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file secrets/root.pass \
  --out-dir ./pki \
  --validity-days 3650 \
  --log-file ./pki/ca.log
```
**2) Issue Intermediate CA**
```bash
echo "imtermediate_passphrase" > secrets/intermediate.pass

python -m micropki.cli ca issue-intermediate \
  --root-cert ./pki/certs/ca.cert.pem \
  --root-key ./pki/private/ca.key.pem \
  --root-pass-file secrets/root.pass \
  --subject "CN=Test Intermediate CA,O=TestIntrOrg" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file secrets/intermediate.pass \
  --out-dir ./pki \
  --validity-days 1825 \
  --pathlen 0 \
  --db-path ./pki/micropki.db \
  --log-file ./pki/ca.log
```
**3) Issue certificates**
```bash
#Server certificate (dns: of ip: SAN is required)
python -m micropki.cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file secrets/intermediate.pass \
  --template server \
  --subject "CN=example.com,O=MyTestOrg" \
  --san dns:example.com \
  --san dns:www.example.com \
  --san ip:192.168.1.10 \
  --out-dir ./pki/certs \
  --validity-days 612 \
  --db-path ./pki/micropki.db \
  --log-file ./pki/ca.log
    
#Client certificate (email:)
python -m micropki.cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file secrets/intermediate.pass \
  --template client \
  --subject "CN=Ivanov Ivan" \
  --san email:IIvan0ff@example.com \
  --out-dir ./pki/certs \
  --validity-days 613 \
  --db-path ./pki/micropki.db \
  --log-file ./pki/ca.log

#Code signing (only dns: or uri:)
python -m micropki.cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file secrets/intermediate.pass \
  --template code_signing \
  --subject "CN=Code Signer" \
  --out-dir ./pki/certs \
  --validity-days 306 \
  --db-path ./pki/micropki.db \
  --log-file ./pki/ca.log
```
**4) Query certificates**
```bash
## List all certificates
python -m micropki.cli ca list-certs --db-path ./pki/micropki.db

## Filter status
python -m micropki.cli ca list-certs --status valid --format table

## Export in JSON, CSV or table format
python -m micropki.cli ca list-certs --format table
python -m micropki.cli ca list-certs --format json
python -m micropki.cli ca list-certs --format csv

## Show certificate by its serial
python -m micropki.cli ca show-cert <insert serial> --db-path ./pki/micropki.db
```
**5) Start repository server**
```bash
python -m micropki.cli repo serve --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs --log-file ./pki/repo.log
```
Endpoints:
```bash
## Root CA
curl -s http://localhost:8080/ca/root
##Intermediate CA
curl -s http://localhost:8080/ca/intermediate
##Certificate by serial
curl -s http://localhost:8080/certificate/<insert serial>
##CRL placeholder (returns code 501)
curl -s http://localhost:8080/crl
```
## Running Tests
```bash
pytest tests/ -v
```
