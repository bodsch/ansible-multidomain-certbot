#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function
import os
import sys
import time
import json
import yaml
# import configparser
import argparse
import logging
import datetime
import subprocess
# import pty
import socket
from dns.resolver import Resolver
import dns.exception

from cryptography import x509
from cryptography.hazmat.backends import default_backend

"""
https://www.programcreek.com/python/example/102802/cryptography.x509.load_der_x509_certificate
"""


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class MemoryLogHandler(logging.Handler):
    """
        Speichert Log-Meldungen in einer internen Liste
    """

    def __init__(self):
        super().__init__()
        self.log_messages = []

    def emit(self, record):
        """Fügt eine formatierte Log-Nachricht der Liste hinzu"""
        if record.levelno >= logging.INFO:  # Speichert nur INFO und höher (kein DEBUG)
            # log_entry = self.format(record)
            log_entry = record.getMessage()  # Holt nur die reine Log-Nachricht
            self.log_messages.append(log_entry)

    def get_logs(self):
        """Gibt alle Logs als String zurück"""
        return "\n".join(self.log_messages)


class DNSResolver:
    """
    """
    def dns_lookup(dns_name, timeout=3, dns_resolvers=[]):
        """
          Perform a simple DNS lookup, return results in a dictionary
        """
        resolver = Resolver()
        resolver.timeout = float(timeout)
        resolver.lifetime = float(timeout)

        result = {}

        if not dns_name:
            return {
                "addrs": [],
                "error": True,
                "error_msg": "No DNS Name for resolving given",
                "name": dns_name,
            }

        if dns_resolvers:
            resolver.nameservers = dns_resolvers
        try:
            records = resolver.resolve(dns_name)
            result = {
                "addrs": [ii.address for ii in records],
                "error": False,
                "error_msg": "",
                "name": dns_name,
            }
        except dns.resolver.NXDOMAIN:
            result = {
                "addrs": [],
                "error": True,
                "error_msg": "No such domain",
                "name": dns_name,
            }
        except dns.resolver.NoNameservers as e:
            result = {
                "addrs": [],
                "error": True,
                "error_msg": repr(e),
                "name": dns_name,
            }
        except dns.resolver.Timeout:
            result = {
                "addrs": [],
                "error": True,
                "error_msg": "Timed out while resolving",
                "name": dns_name,
            }
        except dns.resolver.NameError as e:
            result = {
                "addrs": [],
                "error": True,
                "error_msg": repr(e),
                "name": dns_name,
            }
        except dns.exception.DNSException as e:
            result = {
                "addrs": [],
                "error": True,
                "error_msg": f"Unhandled exception ({repr(e)})",
                "name": dns_name,
            }

        return result


class RenewCertificates():
    """
    """

    def __init__(self):
        """
        """
        self.args = {}
        self.parse_args()

        self.logger = logging.getLogger('certbot-renew')
        self.logger.setLevel(logging.DEBUG)
        self.log_level = self.args.log_level

        self.dry_run = self.args.dry_run
        self.verbose = self.args.verbose

        self.log_file = "/var/log/certbot-renew.log"

        self.log_memory_handler = MemoryLogHandler()
        self.setup_logging()

        self.datetime = time.strftime('%Y%m%d-%H%M')
        self.datetime_readable = time.strftime("%Y-%m-%d")

        self.read_config()
        self.certbot_acme_directory = self.config_acme_dir

    def parse_args(self):
        p = argparse.ArgumentParser(description='renew certbot certicates')

        p.add_argument(
            "-C", "--config",
            required=False,
            default="/etc/certbot/renew.yml",
            help="configuration file")

        p.add_argument(
            "-D", "--directory",
            required=False,
            default="/etc/letsencrypt/live",
            help="located certificates")

        p.add_argument(
            "-L", "--list",
            required=False,
            action='store_true',
            help="list certificates")

        p.add_argument(
            "--dry-run",
            required=False,
            action='store_true',
            help="do nothing")

        p.add_argument(
            "--verbose",
            required=False,
            action='store_true',
            help="verbose output for certbot")

        p.add_argument(
            "--log-level",
            type=str,
            default="INFO",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            help="Setzt das Log-Level (default: INFO)")

        self.args = p.parse_args()

    def setup_logging(self):
        """
            Konfiguriert das Logging mit dem gegebenen Log-Level.
        """
        log_level_numeric = getattr(
            logging, self.log_level)  # Umwandlung von Text in Level
        # DEBUG-Format (kurzer Zeitstempel)
        debug_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s", "%H:%M:%S")

        # Standard-Format für INFO+ (langer Zeitstempel)
        standard_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")

        # Datei-Logging (speichert ALLE Logs mit passendem Format)
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(log_level_numeric)
        file_handler.setFormatter(
            debug_formatter if log_level_numeric == logging.DEBUG else standard_formatter)

        # Konsolen-Logging (INFO und höher)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(standard_formatter)

        # Memory-Logging (für E-Mail, speichert NUR die reine Nachricht)
        self.log_memory_handler.setLevel(logging.INFO)

        # Logger abrufen und Handler hinzufügen
        logger = logging.getLogger()
        logger.setLevel(log_level_numeric)
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.addHandler(self.log_memory_handler)

    def run(self):
        """
        """
        logging.info(f"Renew multiple TLS certificates via certbot at {self.datetime_readable} ...")

        logging.debug("--------------------------------------------------")
        logging.debug(f" config file    : {self.args.config}")
        logging.debug(f" directory      : {self.args.directory}")
        logging.debug(f" log file       : {self.log_file}")
        logging.debug("--------------------------------------------------")

        self.current_certificates = self._current_certificates()

        if self.args.list:
            self.print_current_certs()

        working_well_known = dict()

        running = self._test_running_webserver()
        running = True

        if running:
            working_well_known = self.validate_well_known()

        if len(working_well_known) > 0:
            working_domains = [k for k, v in working_well_known.items() if v]

            logging.info("Check whether the certificates need to be renewed.")

            for domain in working_domains:
                logging.info(f"- {domain}")

                self._diff_domains(domain)
                should_be_renewd = self.check_renew_certificates(domain)

                if should_be_renewd or self.expand:
                    _ = self._renew_certificate(domain=domain)

        logging.info("done ...\n")

    def read_config(self):
        """
        """
        data = None
        self.config_domains = []
        self.config_acme_dir = "/var/www/certbot"
        self.config_base_path = "/etc/certbot/domains"
        self.config_expire_days_limit = 20
        self.config_rsa_key_size = 4096

        self.notification_enabled = False

        if os.path.isfile(self.args.config):
            with open(self.args.config, "r") as stream:
                try:
                    data = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    logging.error(f"  ERROR : '{exc}'")

        if data:
            self.config_domains = data.get('certbot', {}).get('domains', [])
            self.config_acme_dir = data.get('certbot', {}).get('acme_dir', "/var/www/certbot")
            self.config_expire_days_limit = data.get('certbot', {}).get('expire_days_limit', 20)
            self.config_rsa_key_size = data.get('certbot', {}).get('rsa_key_size', 4096)
            self.config_email = data.get('certbot', {}).get('email', 4096)

            notification = data.get("notification", {})

            if notification:
                self.notification_enabled = notification.get(
                    "enabled", False)
                self.notification_smtp_host = notification.get(
                    "smtp", {}).get("server_name", None)
                self.notification_smtp_port = notification.get(
                    "smtp", {}).get("port", 587)
                self.notification_sender = notification.get("sender", None)
                self.notification_recipient = notification.get(
                    "recipient", None)

    def check_renew_certificates(self, domain):
        """
        """
        # logging.debug(f"check_renew_certificates({domain})")
        # logging.debug(self.current_certificates)

        cert_expire = 0

        if len(self.current_certificates) == 0:
            return True

        domain_data = self.current_certificates.get(domain)
        logging.debug(domain_data)

        if domain_data:
            cert_expire = domain_data.get('expire', 0)
            logging.info(f"  expire in {cert_expire} days")

        if cert_expire <= self.config_expire_days_limit:
            return True
        else:
            logging.info("  There is nothing to do, the certificate is currently up to date.")

            msg = None
            should_renewed_in = cert_expire - self.config_expire_days_limit

            if int(should_renewed_in) < 0:
                msg = "  The certificate must be renewed immediately!"
            if int(should_renewed_in) > 4 and int(should_renewed_in) < self.config_expire_days_limit:
                msg = f"  The certificate will be renewed in {should_renewed_in} days."

            if msg:
                logging.info(msg)

            return False

    def check_expand_certificates(self, domain):
        """
        """
        result = True

        logging.debug(f" current certs  {self.current_certificates}")

        return result

    def _renew_certificate(self, domain):
        """
        """
        logging.debug(f"_renew_certificate({domain})")

        _domain_list = self.read_domains_from_config(domain)
        _domains = "--domain "
        _domains += " --domain ".join(_domain_list)

        logging.debug(_domain_list)

        opts = self.__define_certbot_opts(domain=domain, expand=self.expand)

        args = [
            "certbot",
            "certonly",
        ]

        args += opts
        cmd = " ".join(str(x) for x in args)
        cmd += f" {_domains}"

        args.append(_domains)

        # logging.info(f"{args}")

        # master_in_fd, slave_in_fd = pty.openpty()
        # master_out_fd, slave_out_fd = pty.openpty()
        # master_err_fd, slave_err_fd = pty.openpty()
        #
        # try:
        #     p = subprocess.Popen([to_bytes(c) for c in cmd],
        #                          stdin=slave_in_fd,
        #                          stdout=slave_out_fd,
        #                          stderr=slave_err_fd,
        #                          preexec_fn=os.setsid,
        #                          env=env)
        #     out_buffer = b''
        #     err_buffer = b''
        #     rc = p.returncode

        # process = Popen(call, stdout=PIPE, stderr=STDOUT)"
        # .decode("utf-8")

        import shlex
        command = shlex.split(cmd)
        logging.debug(f"  run command: {command}")

        if self.args.dry_run:
            logging.info("run in dry-run ..")
            return

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        rc = process.returncode

        if rc == 0:
            logging.info(f"{stdout}")
            return True
        else:
            _stdout = f"{stdout.rstrip()}"
            _stderr = f"{stderr.rstrip()}"
            _stdout_lines = _stdout.split("\n")
            _stderr_lines = _stderr.split("\n")

            for _so in _stdout_lines:
                logging.error(f"   - stdout: {_so}")

            for _se in _stderr_lines:
                logging.error(f"   - stderr: {_se}")

            return False

    def read_domains_from_config(self, domain):
        """
        """
        logging.debug(f"read_domains_from_config({domain})")

        data = None

        config_file = os.path.join(self.config_base_path, f"{domain}.yml")

        if os.path.exists(config_file):
            with open(config_file, "r") as stream:
                try:
                    data = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    logging.error(msg=f"  ERROR : '{exc}'")

        # DNS verify for domains!
        if data:

            domains = data.get('domains', [])
            domains = self.validate_domains_from_config(domains)

            return domains
        else:
            return []

    def validate_domains_from_config(self, domain_list):
        """
        """
        logging.debug(f"validate_domains_from_config({domain_list})")

        reject_domains = []

        if len(domain_list) > 0:
            _resolver = DNSResolver()

            _domain = []

            for x in domain_list:
                dns_result = _resolver.dns_lookup(x)

                logging.debug(f"  - {dns_result}")

                if not dns_result.get("error"):
                    _domain.append(x)
                else:
                    reject_domains.append(x)

            domain_list = _domain

        if len(reject_domains) > 0:
            logging.warn(f"reject following domains: {reject_domains}")

        return domain_list

    def print_current_certs(self):

        if self.current_certificates:
            logging.info(json.dumps(self.current_certificates, sort_keys=False, indent=2))

    def send_log_email(self):
        """
            Sendet die gespeicherten Logs per E-Mail.
        """
        import smtplib
        from email.mime.text import MIMEText

        email_body = self.log_memory_handler.get_logs()
        subject = f"renew TLS certificates at {socket.getfqdn()} - {self.datetime_readable}"

        logging.debug("sending email")
        logging.debug(f"  - from   : {self.notification_sender}")
        logging.debug(f"  - to     : {self.notification_recipient}")
        logging.debug(f"  - subject: {subject}")
        logging.debug("  - body   :")
        for line in email_body.splitlines():
            logging.debug(f"     {bcolors.FAIL}{line}{bcolors.ENDC}")

        if self.notification_smtp_host and self.notification_sender and self.notification_recipient:
            """
            """
            msg = MIMEText(email_body)
            msg["Subject"] = subject
            msg["From"] = self.notification_sender
            msg["To"] = self.notification_recipient

            try:
                with smtplib.SMTP("smtp.example.com", 587) as server:
                    server.starttls()
                    server.login("deine@email.com", "dein_passwort")
                    server.sendmail(
                        self.notification_sender,
                        self.notification_recipient,
                        msg.as_string()
                    )
                logging.info("email was successfully sent.")
            except Exception as e:
                logging.error("Fehler beim Senden der E-Mail:")
                logging.error(f"  {e}")
        else:
            logging.error("missing smtp server_nemr, or sender, or recipient.")

    def _current_certificates(self):
        """
            current_certificates() {
              echo "current certificates"
              certbot certificates
            }
        """
        alt_names = []
        result = {}

        dateformat = "%d.%m.%Y"

        for currentpath, dirs, files in os.walk(self.args.directory, topdown=True):
            for file in files:
                if file == "fullchain.pem":
                    f = os.path.join(currentpath, file)

                    with open(f, 'br') as cert_content:
                        cert_data = cert_content.read()
                        cert_decoded = x509.load_pem_x509_certificate(cert_data, default_backend())

                        # print(cert_decoded.issuer)

                        subject = cert_decoded.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value.lower()
                        # hash_algorithm = cert_decoded.signature_hash_algorithm

                        SubjectAlternativeName = cert_decoded.extensions.get_extension_for_oid(x509.extensions.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        if SubjectAlternativeName:
                            alt_names = SubjectAlternativeName.value.get_values_for_type(x509.extensions.DNSName)

                        _valid_after = cert_decoded.not_valid_after_utc.strftime(dateformat)
                        _now = datetime.datetime.now(datetime.UTC).strftime(dateformat)
                        expire = (datetime.datetime.strptime(_valid_after, dateformat) - datetime.datetime.strptime(_now, dateformat)).days

                        result[subject] = {}
                        result[subject].update({
                            "expire": expire,
                            "alt_names": alt_names
                        })

        logging.debug(json.dumps(result, sort_keys=False, indent=2))

        return result

    def _test_running_webserver(self, host="0.0.0.0", port=80):
        """
            test_running_webserver
        """
        import socket
        from contextlib import closing

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            if sock.connect_ex((host, port)) == 0:
                # logging.debug("Port is open")
                return True
            else:
                logging.debug("Port {port} on {host} is not open")
                return False

    def validate_well_known(self):
        """
        """
        result = dict()

        if self.config_domains is not None and len(self.config_domains) > 0:
            logging.info("Validate .well-known/acme-challenge")

            for domain in self.config_domains:
                result[domain] = self._well_known_request(domain)

        logging.debug(f" = {result}")

        return result

    def _well_known_request(self, domain):
        """
        """
        import uuid
        import requests

        http_staus_code = None

        result = False

        config_file = os.path.join(self.config_base_path, f"{domain}.yml")

        if os.path.exists(config_file):
            _uid = str(uuid.uuid4())
            uuid_file = os.path.join(self.certbot_acme_directory, ".well-known/acme-challenge", _uid)
            domain_challenge = f"http://{domain}/.well-known/acme-challenge/{_uid}"

            f = open(uuid_file, mode='a')
            f.write(_uid)
            f.close()

            logging.debug(f"test url: {domain_challenge}")

            try:
                x = requests.get(domain_challenge, timeout=3)
                # requests.raise_for_status()
                http_staus_code = x.status_code
                http_message = x.text.strip()
                # logging.info(f"   {domain} with status code: {http_staus_code}")

            except requests.exceptions.HTTPError as errh:
                logging.error(f"Http Error : {errh}")
            except requests.exceptions.ConnectionError as errc:
                logging.error(f"Error Connecting : {errc}")
            except requests.exceptions.Timeout as errt:
                logging.error(f"Timeout Error : {errt}")
            except requests.exceptions.TooManyRedirects as error:
                # Tell the user their URL was bad and try a different one
                logging.error(f"Too many redirects: '{error}'")
            except requests.exceptions.RequestException as err:
                logging.error(f"OOps: Something Else: {err}")

            if http_staus_code and int(http_staus_code) == 200:
                if http_message == _uid:
                    logging.info(f"  - {domain}: success")
                    result = True
                else:
                    logging.error(f"  - {domain}: failed (code: {http_staus_code}, msg: {http_message})")
            else:
                logging.info(f"  - {domain}: failed")

            try:
                os.remove(uuid_file)
            except OSError:
                pass
        else:
            logging.error(f"missing domain config file {domain}.yml")
            result = False

        return result

    def _diff_domains(self, domain):
        """
        """
        # logging.debug(f"::_diff_domains({domain})")

        data = None
        _cert = []
        # logging.debug(self.current_certificates)
        # logging.debug(self.config_domains)

        config_path = os.path.join(self.config_base_path, f"{domain}.yml")

        logging.debug(f"  config file: {config_path}")

        if os.path.exists(config_path):
            with open(config_path, "r") as stream:
                try:
                    data = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    logging.error(f"  ERROR : '{exc}'")

        # logging.debug(f"  data: {data}")

        _domains = data.get("domains", [])
        _domains = sorted(_domains)

        # logging.debug(f"  domains: {_domains}")

        if self.current_certificates:
            domain_avail = self.current_certificates.get(domain, None)
            if domain_avail:
                logging.debug(f"  domain: {domain_avail}")

                alt_names = domain_avail.get("alt_names")
                logging.debug(f"  alt name : {alt_names}")
                _cert = sorted(alt_names)  # self.current_certificates.get(domain, {}).get("alt_names"))
            else:
                pass

        # logging.debug(f" - {_domains} - {type(_domains)}")
        logging.debug(f" - {_cert}")

        diff = list(set(_domains) - set(_cert))

        if len(diff) == 0:
            self.expand = False
        else:
            self.expand = True

            logging.info("you must expand your certifiacte!")
            logging.info(diff)

    def __define_certbot_opts(self, domain, expand=False):
        """
        """
        # local domain="${1}"
        # local expand="${2:-}"
        # local CERTBOT_CERT_FILE=$(define_cert_file ${domain})
        cmd = []
        if expand:
            cmd.append("--expand")

        if self.args.dry_run:
            cmd.append("--dry-run")

        cmd.append("--webroot")
        cmd.append("--webroot-path")
        cmd.append(self.certbot_acme_directory)
        cmd.append("--rsa-key-size")
        cmd.append(self.config_rsa_key_size)
        cmd.append("--cert-path")
        cmd.append(f"/etc/letsencrypt/live/{domain}")
        cmd.append("--agree-tos")
        cmd.append("--email")
        cmd.append(self.config_email)
        cmd.append("-n")

        if self.verbose or self.log_level == "DEBUG":
            cmd.append("--verbose")

        return cmd


def main():
    p = RenewCertificates()
    p.run()


if __name__ == '__main__':
    main()
