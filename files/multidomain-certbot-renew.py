#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function
import os
import json
import yaml
import configparser
import argparse
import logging
import datetime
import subprocess
import pty

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

        # create file handler which logs even debug messages
        fh = logging.FileHandler('certbot-renew.log')
        fh.setLevel(logging.DEBUG)

        # create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s')

        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # add the handlers to the logger
        # self.logger.addHandler(fh)
        self.logger.addHandler(ch)

        self.read_config()

        self.certbot_acme_directory = self.config_acme_dir

        print("--------------------------------------------------")
        print(f" config file    : {self.args.config}")
        print(f" directory      : {self.args.directory}")
        print(f" list           : {self.args.list}")
        print(f" dry-run        : {self.args.dry_run}")
        print("--------------------------------------------------")

        #

    def parse_args(self):
        p = argparse.ArgumentParser(description='renew certbot certicates')

        p.add_argument(
            "-C", "--config",
            required = False,
            default = "/etc/certbot/renew.yml",
            help = "configuration file")

        p.add_argument(
            "-D", "--directory",
            required = False,
            default = "/etc/letsencrypt/live",
            help = "located certificates")

        p.add_argument(
            "-L", "--list",
            required = False,
            action='store_true',
            help = "list certificates")

        p.add_argument(
            "--dry-run",
            required = False,
            action='store_true',
            help = "do nothing")

        self.args = p.parse_args()

    def run(self):
        """
        """
        pass

        self.current_certificates = self._current_certificates()

        running = self._test_running_webserver()

        if self.config_domains is not None and len(self.config_domains) > 0:

            for domain in self.config_domains:

                working_well_known = self._validate_well_known(domain)

                if working_well_known:
                    self._diff_domains(domain)

                    should_be_renewd = self.check_renew_certificates(domain)

                    if should_be_renewd:
                        self._renew_certificate(domain=domain)


    def read_config(self):
        """
        """
        data = None
        self.config_domains = []
        self.config_acme_dir = "/var/www/certbot"
        self.config_base_path = "/etc/certbot/domains"
        self.config_expire_days_limit = 20
        self.config_rsa_key_size = 4096

        if os.path.isfile(self.args.config):
            with open(self.args.config, "r") as stream:
                try:
                    data = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    self.logger.error(f"  ERROR : '{exc}'")

        if data:
            self.config_domains = data.get('certbot', {}).get('domains', [])
            self.config_acme_dir = data.get('certbot', {}).get('acme_dir', "/var/www/certbot")
            self.config_expire_days_limit = data.get('certbot', {}).get('expire_days_limit', 20)
            self.config_rsa_key_size = data.get('certbot', {}).get('rsa_key_size', 4096)
            self.config_email = data.get('certbot', {}).get('email', 4096)


    def check_renew_certificates(self, domain):
        """
        """
        self.logger.info(domain)

        domain_data = self.current_certificates.get(domain)
        cert_expire = domain_data.get('expire', 0)

        self.logger.info(domain_data)
        self.logger.info(f"  expire in {cert_expire} days")

        _domains = []

        if cert_expire <= self.config_expire_days_limit:
            return True
        else:
            self.logger.info(f"nothing to do, cert is up to day. renewal in { cert_expire - self.config_expire_days_limit } days.")
            return False

    def _renew_certificate(self, domain):
        """
        """
        _domain_list = self.read_domains_from_config(domain)
        _domains = "--domain "
        _domains += " --domain ".join(_domain_list)

        opts = self.__define_certbot_opts(domain=domain, expand=self.expand)

        args = [
            "certbot",
            "certonly",
        ]

        args += opts
        cmd = " ".join(str(x) for x in args)
        cmd += f" {_domains}"

        args.append(_domains)

        self.logger.info(f"{args}")

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
        self.logger.info(f"{command} / {type(command)}")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        rc = process.returncode

        if rc == 0:
            self.logger.info(f"{stdout}")
        else:
          self.logger.error(f"{str(stdout)}")
          self.logger.error(f"{stderr}")

        #self.logger.debug(process)

    def read_domains_from_config(self, domain):
        """
        """
        data = None

        config_path = os.path.join(self.config_base_path, f"{domain}.yml")

        if os.path.exists(config_file):
            with open(config_file, "r") as stream:
                try:
                    data = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    self.module.log(msg=f"  ERROR : '{exc}'")

        if data:
            return data.get('domains', [])
        else:
            return []

    def _current_certificates(self):
        """
            current_certificates() {
              echo "current certificates"
              certbot certificates
            }
        """
        alt_names = []
        result={}

        dateformat = "%d.%m.%Y"

        for currentpath, dirs, files in os.walk(self.args.directory, topdown=True):
            for file in files:
                if file == "fullchain.pem":
                    f = os.path.join(currentpath, file)

                    with open(f, 'br') as cert_content:
                        cert_data = cert_content.read()
                        cert_decoded = x509.load_pem_x509_certificate(cert_data, default_backend())

                        #print(cert_decoded.issuer)

                        subject = cert_decoded.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value.lower()
                        hash_algorithm = cert_decoded.signature_hash_algorithm

                        SubjectAlternativeName = cert_decoded.extensions.get_extension_for_oid(x509.extensions.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        if SubjectAlternativeName:
                            alt_names = SubjectAlternativeName.value.get_values_for_type(x509.extensions.DNSName)

                        _valid_after = cert_decoded.not_valid_after_utc.strftime(dateformat)
                        _now         = datetime.datetime.now(datetime.UTC).strftime(dateformat)
                        expire        = (datetime.datetime.strptime(_valid_after, dateformat) - datetime.datetime.strptime(_now, dateformat)).days

                        result[subject] = {}
                        result[subject].update({
                            "expire": expire,
                            "alt_names": alt_names
                            })

        self.logger.info(json.dumps(result, sort_keys=False, indent=2))

        return result

    def _test_running_webserver(self, host="0.0.0.0", port=80):
        """
            test_running_webserver
        """
        import socket
        from contextlib import closing

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            if sock.connect_ex((host, port)) == 0:
                self.logger.debug("Port is open")
                return True
            else:
                self.logger.debug("Port is not open")
                return False

    def _validate_well_known(self, domain):
        """
        """
        import uuid
        import requests

        result = {}

        # config_base_path = "/etc/certbot/domains"

        result[domain] = False
        config_path = os.path.join(self.config_base_path, f"{domain}.yml")

        if os.path.exists(config_path):
            _uid = str(uuid.uuid4())
            uuid_file = os.path.join(self.certbot_acme_directory, ".well-known/acme-challenge", _uid)
            domain_challenge = f"http://{domain}/.well-known/acme-challenge/{_uid}"

            open(uuid_file, mode='a').close()

            x = requests.get(domain_challenge)

            self.logger.info(f"   {domain} with status code: {x.status_code}")

            if x.status_code == 200:
                result[domain] = True

            try:
                os.remove(uuid_file)
            except OSError:
                pass
        else:
            self.logger.error(f"missing domain config file {domain}.yml")
            result = None

        return result

    def _diff_domains(self, domain):
        """
        """
        data = None
        self.logger.debug(self.current_certificates)
        self.logger.debug(self.config_domains)

        config_path = os.path.join(self.config_base_path, f"{domain}.yml")
        if os.path.exists(config_path):
            with open(config_path, "r") as stream:
                try:
                    data = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    self.logger.error(f"  ERROR : '{exc}'")

        # self.logger.debug(f"{data}")

        _domains = sorted(data.get("domains"))
        _cert   = sorted(self.current_certificates.get(domain).get("alt_names"))

        # self.logger.debug(f" - {_domains} - {type(_domains)}")
        # self.logger.debug(f" - {_cert} - {type(_cert)}")

        diff = list(set(_domains) - set(_cert))

        if len(diff) == 0:
            self.expand=False
        else:
            self.expand = True

            self.logger.info("you must expand your certifiacte!")
            self.logger.info(diff)

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

        return cmd


def main():
    p = RenewCertificates()
    result = p.run()


if __name__ == '__main__':
    main()
