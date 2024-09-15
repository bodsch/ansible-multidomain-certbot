# ansible rolle `multi-certbot`

certbot role for multiple ACME certificates


[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-multidomain-certbot/main.yml?branch=main)][ci]
[![GitHub issues](https://img.shields.io/github/issues/bodsch/ansible-multidomain-certbot)][issues]
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/bodsch/ansible-multidomain-certbot)][releases]
[![Ansible Downloads](https://img.shields.io/ansible/role/d/bodsch/multidomain_certbot?logo=ansible)][galaxy]

[ci]: https://github.com/bodsch/ansible-multidomain-certbot/actions
[issues]: https://github.com/bodsch/ansible-multidomain-certbot/issues?q=is%3Aopen+is%3Aissue
[releases]: https://github.com/bodsch/ansible-multidomain-certbot/releases
[galaxy]: https://galaxy.ansible.com/ui/standalone/roles/bodsch/multidomain_certbot/

## Requirements & Dependencies

Ansible Collections

- [bodsch.core](https://github.com/bodsch/ansible-collection-core)

```bash
ansible-galaxy collection install bodsch.core
```
or
```bash
ansible-galaxy collection install --requirements-file collections.yml
```

## tested operating systems

* ArchLinux
* Debian based
    - Debian 11 / 12
    - Ubuntu 22.04


## usage

```yaml
multi_certbot_conf_directory: /etc/letsencrypt

multi_certbot_tls_certificates: []

multi_certbot_staging_args:
  - --test-cert
  - --dry-run

multi_certbot_email: "pki@test.com"
multi_certbot_www_directory: /var/www/certbot
multi_certbot_well_known_directory: "{{ multi_certbot_www_directory }}/.well-known/acme-challenge"

multi_certbot_rsa_key_size: 4096
```

### `multi_certbot_tls_certificates`

```yaml
multi_certbot_tls_certificates:
  - domain: foo.bar
    subdomains:
  - domain: bar.foo
    subdomains: www.bar.foo
  - domain: test.com
    subdomains:
      - www.test.com
      - www1.test.com
      - www2.test.com
```

## certificate renew

Alle vorliegenden Zertifikate werden über das Script `/usr/local/bin/certbot-renew.sh` erneuert.

Diese werden ausschließlich via *webroot* erneuert!
Um das zu gewährleisten wird die Erreichbarkeit der Domain geprüft.
Hierzu wird eine temporäre zufällige Datei im Verzeichniss `multi_certbot_well_known_directory` erstellt und diese
anschließend über `curl` abgefragt.

Desweiteren wird geprüft, ob sämtliche konfigurierte Domains im Zertifikat verfügbar sind.

Ist dies nicht der Fall, wird das Zertifikat automatisch erweitert.


## Contribution

Please read [Contribution](CONTRIBUTING.md)

## Development,  Branches (Git Tags)

The `master` Branch is my *Working Horse* includes the "latest, hot shit" and can be complete broken!

If you want to use something stable, please use a [Tagged Version](https://github.com/bodsch/ansible-multidomain-certbot/tags)!

## Author

- Bodo Schulz

## License

[Apache](LICENSE)

**FREE SOFTWARE, HELL YEAH!**

