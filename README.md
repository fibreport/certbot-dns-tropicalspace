certbot-dns-tropicalspace
=========================

**Certbot DNS-01 authenticator plugin for `tropicalspace.de`.**

This plugin lets Certbot solve the DNS-01 challenge by creating and removing TXT records via the
[tropicalspace.de developer API](https://tropicalspace.de/entwickler). It works for wildcard certificates and for servers
that are not reachable from the internet.

- Uses an API key that may **only** change `_acme-challenge` TXT records – a leaked key cannot redirect your website.
- Finds the right zone on its own (also for zones of subdomains).
- Waits until the record is on all tropicalspace.de nameservers before Let's Encrypt checks it.
- Removes exactly the record it added, so parallel challenges (e.g. `example.de` and `*.example.de`) do not interfere.


## 1. Create an API key

In the tropicalspace.de customer center go to **Profil › API-Schlüssel › Neuer API-Schlüssel**:

- **Rechte:** choose the template **Let's Encrypt** and the zones you need certificates for
  (rights `dns:write`, type `TXT`, names `_acme-challenge, _acme-challenge.*`).
- **IP-Adressen:** enter the address(es) of the server running Certbot (optional, recommended).

Copy the key (`tsk_…`) right away – it is shown only once.


## 2. Installation

Certbot comes from snap as usual. The plugin is **not in the Snap Store** (nor on PyPI): each
[release](https://github.com/fibreport/certbot-dns-tropicalspace/releases) has the plugin snap attached, which you
install by hand.

### Certbot (snap) and the plugin snap – recommended

```bash
# Certbot itself, if not installed yet
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# the plugin from the latest release (on arm64 servers: certbot-dns-tropicalspace_arm64.snap)
wget https://github.com/fibreport/certbot-dns-tropicalspace/releases/latest/download/certbot-dns-tropicalspace_amd64.snap
sudo snap install --dangerous ./certbot-dns-tropicalspace_amd64.snap

# allow Certbot to load the plugin and connect both snaps
sudo snap set certbot trust-plugin-with-root=ok
sudo snap connect certbot:plugin certbot-dns-tropicalspace
```

`--dangerous` is needed because the snap does not come from the Snap Store; for the same reason it is **not updated
automatically** – install the .snap of a newer release the same way. Instead of downloading you can build it yourself
from a checkout with `snapcraft pack`.

If the names differ on your system, check `snap connections certbot-dns-tropicalspace`.

### Certbot from pip – alternative

Without snap, install the plugin from GitHub into the same Python environment as Certbot:

```bash
sudo python3 -m venv /opt/certbot
sudo /opt/certbot/bin/pip install certbot git+https://github.com/fibreport/certbot-dns-tropicalspace.git
sudo ln -s /opt/certbot/bin/certbot /usr/local/bin/certbot
```

A specific release: `git+https://github.com/fibreport/certbot-dns-tropicalspace.git@v1.0.0`; update with `--upgrade`.

Verify that Certbot sees the plugin:

```bash
sudo certbot plugins
```

```text
* dns-tropicalspace
Description: Obtain certificates using a DNS TXT record (if you are using tropicalspace.de for DNS).
```


## 3. Credentials file

Create `/etc/letsencrypt/dns-tropicalspace.ini`:

```ini
# Required: API key from the customer center (Profil › API-Schlüssel)
dns_tropicalspace_api_key = tsk_XXXXXXXX_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Optional: API endpoint (default https://api.tropicalspace.de/v1)
# dns_tropicalspace_api_endpoint = https://api.tropicalspace.de/v1
```

The file must be readable only by root, otherwise Certbot refuses it:

```bash
sudo chown root:root /etc/letsencrypt/dns-tropicalspace.ini
sudo chmod 600 /etc/letsencrypt/dns-tropicalspace.ini
```


## 4. Usage

### Single domain

```bash
sudo certbot certonly \
  --authenticator dns-tropicalspace \
  --dns-tropicalspace-credentials /etc/letsencrypt/dns-tropicalspace.ini \
  -d example.de
```

### Wildcard certificate

```bash
sudo certbot certonly \
  --authenticator dns-tropicalspace \
  --dns-tropicalspace-credentials /etc/letsencrypt/dns-tropicalspace.ini \
  -d example.de \
  -d '*.example.de'
```

Certbot remembers the plugin and its options; `certbot renew` renews without further input.

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--dns-tropicalspace-credentials` | – | Path to the credentials INI file |
| `--dns-tropicalspace-sync-timeout` | `120` | Seconds to wait until the record is on all tropicalspace.de nameservers (`0` = do not wait) |
| `--dns-tropicalspace-propagation-seconds` | `10` | Additional seconds Certbot waits before asking Let's Encrypt to check |


## Troubleshooting

Errors contain the message of the API (in German) and a hint in English.

- **`401 invalid_api_key`** – the key in the INI file is wrong, revoked or expired. Create a new one in the customer center.
- **`403 ip_not_allowed`** – the server connects with an address that is not allowed for the key (often IPv6).
  The address the API saw is in the message; add it to the key's IP addresses.
- **`403 permission_denied`** – the key may not change this name, e.g. a zone that is not selected in the key.
- **`No DNS zone for … found`** – the domain does not use the tropicalspace.de nameservers, or the key has no right for its zone.
- **Let's Encrypt cannot find the record** – check that the domain points to the tropicalspace.de nameservers.
  If the zone has CAA records, one of them must allow `0 issue "letsencrypt.org"`.

Every change and every error of a key is listed for 90 days in the customer center next to the key.


## Development

```bash
pip install -e '.[test]' ruff flake8
ruff format --check . && ruff check . && flake8 .  # PEP 8: 79 characters, docstrings 72
python -m pytest tests
```

Against a local tropicalspace.de installation `http://localhost` and `http://*.localhost` endpoints are accepted;
all other endpoints must use HTTPS.

### Release

1. Raise `version` in `setup.py` and `__version__` in `certbot_dns_tropicalspace/__init__.py` (a test checks they match).
2. Tag the commit (`v1.0.1`) and push the tag; the workflow builds the snaps (amd64, arm64) and the Python package and attaches them to the GitHub release.


## License

Apache License 2.0, see `LICENSE`.
